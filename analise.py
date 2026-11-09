"""Protótipo do Projeto de Aplicação: priorização de vulnerabilidades orientada a risco.

Etapas
  1. Carrega os dados públicos coletados (NVD: registros e histórico de alterações;
     KEV da CISA; EPSS diário do FIRST).
  2. Reconstrói os atributos de cada CVE na data de decisão t_d (ponto no tempo).
  3. Treina regressão logística e gradient boosting, calibra e avalia no teste.
  4. Simula um ambiente corporativo e compara estratégias de priorização.
  5. Compara funções de risco com CVEs reais.

Uso: python3 analise.py <pasta_dados> <pasta_saida>
"""
import json, math, sys, os
from datetime import date, timedelta
import numpy as np
import pandas as pd
from scipy.stats import kendalltau
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import average_precision_score, brier_score_loss, precision_recall_curve

RNG_BASE = 20251101
TREINO_INI, TREINO_FIM = date(2023, 1, 1), date(2023, 12, 31)
TESTE_INI, TESTE_FIM = date(2025, 1, 1), date(2025, 10, 31)
CORTE_MODELO = date(2024, 1, 1)
HORIZONTE = date(2026, 11, 1)
METRICAS_CVSS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------

def proximo_ciclo(d):
    """Primeiro dia do mês seguinte: data do primeiro ciclo de priorização."""
    return date(d.year + (d.month == 12), d.month % 12 + 1, 1)


def ciclos(ini, fim):
    out, d = [], ini
    while d <= fim:
        out.append(d)
        d = proximo_ciclo(d)
    return out


def cvss31_base(cod):
    """Nota base CVSS 3.1 a partir do código de 8 letras (AV AC PR UI S C I A)."""
    if not cod or "?" in cod or len(cod) != 8:
        return np.nan
    av, ac, pr, ui, s, c, i, a = cod
    AV = {"N": .85, "A": .62, "L": .55, "P": .2}[av]
    AC = {"L": .77, "H": .44}[ac]
    if s == "U":
        PR = {"N": .85, "L": .62, "H": .27}[pr]
    else:
        PR = {"N": .85, "L": .68, "H": .5}[pr]
    UI = {"N": .85, "R": .62}[ui]
    cia = {"H": .56, "L": .22, "N": 0}
    iss = 1 - (1 - cia[c]) * (1 - cia[i]) * (1 - cia[a])
    imp = 6.42 * iss if s == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
    if imp <= 0:
        return 0.0
    expl = 8.22 * AV * AC * PR * UI
    base = min(imp + expl, 10) if s == "U" else min(1.08 * (imp + expl), 10)
    return math.ceil(base * 10 - 1e-9) / 10


def d(s):
    return date.fromisoformat(s)

# ----------------------------------------------------------------------------
# 1. Carga
# ----------------------------------------------------------------------------

def carregar(pasta):
    nvd = json.load(open(os.path.join(pasta, "nvd.json")))
    src_nome = {v: k for k, v in nvd["src"].items()}
    # 2023: registros da API de CVEs (data de publicação, CNA e situação)
    cve = pd.DataFrame(nvd["cve"], columns=["cve", "pub", "src", "rejeitada"]).drop_duplicates("cve")
    # 2025: evento "New CVE Received" do histórico, que traz a data de publicação e a CNA
    rec = pd.DataFrame(nvd["rec"], columns=["cve", "data", "src", "vet", "cwe", "v4"])
    rec = rec.sort_values("data").drop_duplicates("cve")
    rej = {r[0] for r in nvd.get("rej", [])}
    cve25 = pd.DataFrame({"cve": rec["cve"], "pub": rec["data"], "src": rec["src"],
                          "rejeitada": rec["cve"].isin(rej).astype(int)})
    cve = pd.concat([cve, cve25[~cve25["cve"].isin(cve["cve"])]], ignore_index=True)
    cve["pub"] = cve["pub"].map(d)
    cve["src_nome"] = cve["src"].map(src_nome)
    rec = rec.drop(columns=["src"])
    rec["data"] = rec["data"].map(d)
    ana = pd.DataFrame(nvd["ana"], columns=["cve", "data", "vet", "cwe"])
    ana["data"] = ana["data"].map(d)
    ana = ana.sort_values("data").drop_duplicates("cve")
    kev = json.load(open(os.path.join(pasta, "kev.json")))
    kev = pd.DataFrame(kev["rows"], columns=["cve", "data_kev", "fab", "prod", "ransom"])
    kev["data_kev"] = kev["data_kev"].map(d)
    kev = kev.sort_values("data_kev").drop_duplicates("cve")
    z = np.load(os.path.join(pasta, "epss", "epss_2025.npz"))
    ids = ["CVE-2025-%04d" % n for n in z["idx"]]
    epss = {}
    for ds in z["dates"]:
        arr = z["d" + str(ds).replace("-", "")].astype(float)
        v = np.where(arr == 65535, np.nan, arr / 65535)
        epss[d(str(ds))] = pd.Series(v, index=ids)
    p23 = os.path.join(pasta, "epss", "epss_2023.json")
    if os.path.exists(p23):
        e23 = json.load(open(p23))
        for ds, mp in e23.items():
            epss[d(ds)] = pd.Series({"CVE-2023-" + k: v for k, v in mp.items()}, dtype=float)
    base = cve.merge(rec.add_prefix("rec_").rename(columns={"rec_cve": "cve"}), on="cve", how="left")
    base = base.merge(ana.add_prefix("ana_").rename(columns={"ana_cve": "cve"}), on="cve", how="left")
    base = base.merge(kev[["cve", "data_kev"]], on="cve", how="left")
    return base, kev, epss

# ----------------------------------------------------------------------------
# 2. Atributos no ponto no tempo
# ----------------------------------------------------------------------------

def estado_em(base, t):
    """Vetor CVSS, CWE e a data da evidência usada, como estavam na data t.

    Regra: análise da NVD se concluída até t; senão, dados da CNA recebidos na
    publicação (disponíveis apenas a partir de 2024 no histórico); senão, ausente.
    """
    t_ser = t if isinstance(t, pd.Series) else pd.Series([t] * len(base), index=base.index)
    usa_ana = base["ana_data"].notna() & (base["ana_data"] <= t_ser) & (base["ana_vet"].fillna("") != "")
    usa_rec = ~usa_ana & base["rec_data"].notna() & (base["rec_data"] <= t_ser)
    vet = np.where(usa_ana, base["ana_vet"], np.where(usa_rec, base["rec_vet"], ""))
    cwe_ana = base["ana_cwe"].fillna("")
    cwe = np.where(usa_ana & (cwe_ana != ""), cwe_ana, np.where(usa_rec, base["rec_cwe"].fillna(""), ""))
    data_ev = np.where(usa_ana, base["ana_data"], np.where(usa_rec, base["rec_data"], None))
    fonte = np.where(usa_ana, "nvd", np.where(usa_rec, "cna", "ausente"))
    return pd.DataFrame({"vet": vet, "cwe": cwe, "data_ev": data_ev, "fonte": fonte}, index=base.index)


class Codificador:
    def __init__(self, top_cwe=25, top_src=40):
        self.top_cwe, self.top_src = top_cwe, top_src

    def _cols(self, base, est):
        X = pd.DataFrame(index=base.index)
        v = est["vet"].fillna("")
        for k, m in enumerate(METRICAS_CVSS):
            X[m] = v.map(lambda s: s[k] if len(s) == 8 else "ausente")
        X["cwe"] = est["cwe"].fillna("").map(lambda s: "CWE-" + s.split(".")[0] if s else "ausente")
        X["src"] = base["src_nome"].fillna("ausente")
        return X

    def ajustar(self, base, est):
        X = self._cols(base, est)
        self.cwes = set(X["cwe"].value_counts().index[: self.top_cwe])
        self.srcs = set(X["src"].value_counts().index[: self.top_src])
        X = self._limitar(X)
        self.ohe = OneHotEncoder(handle_unknown="ignore", min_frequency=5).fit(X)
        self.cats = {c: sorted(X[c].unique()) for c in X.columns}
        return self

    def _limitar(self, X):
        X = X.copy()
        X["cwe"] = X["cwe"].where(X["cwe"].isin(self.cwes) | (X["cwe"] == "ausente"), "outra")
        X["src"] = X["src"].where(X["src"].isin(self.srcs), "outra")
        return X

    def matriz(self, base, est, ep=None):
        X = self._limitar(self._cols(base, est))
        Xo = self.ohe.transform(X)
        if ep is not None:
            from scipy import sparse
            lep = np.log10(np.clip(ep, 1e-5, 1))
            falta = np.isnan(lep)
            Xo = sparse.hstack([Xo, sparse.csr_matrix(np.column_stack([np.where(falta, -5, lep) / 5 + 1, falta]))]).tocsr()
        cols = []
        for c in X.columns:
            cats = list(dict.fromkeys(self.cats[c] + ["outra", "ausente"]))
            cod = pd.Categorical(X[c], categories=cats).codes.astype(float)
            cod[cod < 0] = np.nan
            cols.append(cod)
        Xn = np.column_stack(cols)
        nota = est["vet"].map(cvss31_base).astype(float).values
        Xn = np.column_stack([Xn, nota])
        if ep is not None:
            Xn = np.column_stack([Xn, np.log10(np.clip(ep, 1e-5, 1))])
        return Xo, Xn


def montar_conjunto(base, ini, fim):
    """CVEs com identificador do próprio ano, publicadas no intervalo e não rejeitadas."""
    pref = f"CVE-{ini.year}-"
    df = base[(base["pub"] >= ini) & (base["pub"] <= fim) & (base["rejeitada"] == 0)
              & base["cve"].str.startswith(pref)].copy()
    df["t_d"] = df["pub"].map(proximo_ciclo)
    conhecida = df["data_kev"].notna() & (df["data_kev"] <= df["t_d"])
    excl = int(conhecida.sum())
    df = df[~conhecida].copy()
    lim = df["t_d"].map(lambda t: t + timedelta(days=365))
    df["y"] = (df["data_kev"].notna() & (df["data_kev"] > df["t_d"]) & (df["data_kev"] <= lim)).astype(int)
    est = estado_em(df, df["t_d"])
    return df, est, excl


def auditar(df, est, t):
    """Verifica que nenhuma evidência usada tem data posterior à data de decisão."""
    t_ser = t if isinstance(t, pd.Series) else pd.Series([t] * len(df), index=df.index)
    datas = est["data_ev"]
    m = datas.notna()
    violacoes = int((pd.to_datetime(datas[m]) > pd.to_datetime(t_ser[m])).sum())
    assert violacoes == 0, f"{violacoes} atributos com data posterior a t"
    return violacoes

# ----------------------------------------------------------------------------
# 3. Modelos
# ----------------------------------------------------------------------------

def prec_rec_at_k(y, s, frac):
    k = max(1, int(round(frac * len(y))))
    ordem = np.argsort(-s, kind="stable")[:k]
    tp = y[ordem].sum()
    return tp / k, tp / max(1, y.sum())


def bootstrap_ap(y, s, n=1000, seed=0):
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if y[i].sum() == 0:
            continue
        vals.append(average_precision_score(y[i], s[i]))
    return np.percentile(vals, [2.5, 97.5])


class Platt:
    def fit(self, s, y):
        self.lr = LogisticRegression(C=1e6, max_iter=1000).fit(np.log(np.clip(s, 1e-6, 1 - 1e-6) / (1 - np.clip(s, 1e-6, 1 - 1e-6))).reshape(-1, 1), y)
        return self

    def __call__(self, s):
        x = np.log(np.clip(s, 1e-6, 1 - 1e-6) / (1 - np.clip(s, 1e-6, 1 - 1e-6))).reshape(-1, 1)
        return self.lr.predict_proba(x)[:, 1]


def epss_em(epss, cves, ts):
    """Pontuação EPSS de cada CVE no arquivo diário da data de decisão (NaN se ausente)."""
    cves = pd.Series(list(cves)); ts = pd.Series(list(ts))
    out = np.full(len(cves), np.nan)
    for t, idx in ts.groupby(ts).groups.items():
        if t in epss:
            ser = epss[t]
            ser = ser[~ser.index.duplicated()]
            out[list(idx)] = ser.reindex(cves.iloc[list(idx)]).values
    return out


def _ajusta_lr(Xo, y, fit, val):
    melhor = None
    for C in (0.01, 0.1, 1.0):
        m = LogisticRegression(C=C, class_weight="balanced", max_iter=3000).fit(Xo[fit], y[fit])
        ap = average_precision_score(y[val], m.predict_proba(Xo[val])[:, 1])
        if melhor is None or ap > melhor[0]:
            melhor = (ap, {"C": C}, m)
    return melhor


def _ajusta_hgb(Xn, y, fit, val):
    ncat = len(METRICAS_CVSS) + 2
    melhor = None
    for lr_ in (0.05, 0.1):
        for folhas in (7, 15):
            m = HistGradientBoostingClassifier(learning_rate=lr_, max_leaf_nodes=folhas, max_iter=300,
                                               l2_regularization=1.0, class_weight="balanced",
                                               categorical_features=list(range(ncat)),
                                               early_stopping=False, random_state=0)
            m.fit(Xn[fit], y[fit])
            ap = average_precision_score(y[val], m.predict_proba(Xn[val])[:, 1])
            if melhor is None or ap > melhor[0]:
                melhor = (ap, {"learning_rate": lr_, "max_leaf_nodes": folhas}, m)
    return melhor


def treinar(tr, est_tr, ep_tr):
    """Ajuste em jan-ago/2023; seleção de hiperparâmetros, escolha do modelo e calibração em set-dez/2023.

    Variantes: só metadados (CVSS, CWE, CNA); metadados com a pontuação EPSS vigente em t_d;
    e EPSS isolado calibrado para o horizonte de 365 dias.
    """
    fit = (tr["pub"] <= date(2023, 8, 31)).values
    val = ~fit
    y = tr["y"].values
    cod = Codificador().ajustar(tr[fit], est_tr[fit])
    Xo_m, Xn_m = cod.matriz(tr, est_tr)
    Xo_e, Xn_e = cod.matriz(tr, est_tr, ep_tr)
    res = {"cod": cod, "variantes": {}}
    for nome, (X, fn, usa_ep, kind) in {
            "lr_meta": (Xo_m, _ajusta_lr, False, "lr"), "hgb_meta": (Xn_m, _ajusta_hgb, False, "hgb"),
            "lr_epss": (Xo_e, _ajusta_lr, True, "lr"), "hgb_epss": (Xn_e, _ajusta_hgb, True, "hgb")}.items():
        ap, params, m = fn(X, y, fit, val)
        cal = Platt().fit(m.predict_proba(X[val])[:, 1], y[val])
        res["variantes"][nome] = {"modelo": m, "params": params, "ap_val": ap, "cal": cal, "usa_ep": usa_ep, "kind": kind}
    ep0 = np.nan_to_num(ep_tr, nan=1e-5)
    cal = Platt().fit(ep0[val], y[val])
    res["variantes"]["epss_cal"] = {"modelo": None, "params": {}, "ap_val": average_precision_score(y[val], ep0[val]),
                                    "cal": cal, "usa_ep": True, "kind": "epss"}
    cands = ["lr_epss", "hgb_epss", "epss_cal"]
    res["final"] = max(cands, key=lambda k: res["variantes"][k]["ap_val"])
    res["n_fit"], res["n_val"] = int(fit.sum()), int(val.sum())
    res["pos_fit"], res["pos_val"] = int(y[fit].sum()), int(y[val].sum())
    return res


def prever(mod, base, est, qual, ep=None):
    v = mod["variantes"][qual]
    if v["kind"] == "epss":
        bruto = np.nan_to_num(ep, nan=1e-5)
    else:
        Xo, Xn = mod["cod"].matriz(base, est, ep if v["usa_ep"] else None)
        bruto = v["modelo"].predict_proba(Xo if v["kind"] == "lr" else Xn)[:, 1]
    return np.clip(v["cal"](bruto), 1e-4, 1.0)

# ----------------------------------------------------------------------------
# 4. Simulação
# ----------------------------------------------------------------------------

CLASSES = {
    # nome: (participação, faixa CIA, exposição e, esforço em horas por item, ativos por CVE)
    "servidor_exposto": (0.05, (4, 5), 1.0, 3.0, 2),
    "servidor_interno": (0.20, (3, 5), 0.7, 2.0, 5),
    "estacao":          (0.65, (1, 3), 0.7, 0.25, 40),
    "rede":             (0.10, (3, 5), 1.0, 4.0, 3),
}


def gerar_inventario(n, rng):
    nomes = list(CLASSES)
    part = np.array([CLASSES[c][0] for c in nomes])
    cls = rng.choice(nomes, size=n, p=part / part.sum())
    ativos = []
    for k, c in enumerate(cls):
        lo, hi = CLASSES[c][1]
        cia = rng.integers(lo, hi + 1, size=3)
        ativos.append({"ativo": k, "classe": c, "c": cia[0], "i": cia[1], "a": cia[2], "e": CLASSES[c][2],
                       "esforco": CLASSES[c][3]})
    inv = pd.DataFrame(ativos)
    inv["I_media"] = (inv["c"] + inv["i"] + inv["a"]) / 15 * inv["e"]
    inv["I_max"] = inv[["c", "i", "a"]].max(axis=1) / 5 * inv["e"]
    return inv


def gerar_itens(teste, inv, rng, prob_presenca=0.15):
    """Distribui CVEs do período de teste em ativos do inventário sintético."""
    presentes = teste[rng.random(len(teste)) < prob_presenca]
    por_classe = {c: inv.index[inv["classe"] == c].values for c in CLASSES}
    nomes = list(CLASSES)
    part = np.array([CLASSES[c][0] for c in nomes]) ** 0.5
    linhas = []
    for idx, r in presentes.iterrows():
        c = rng.choice(nomes, p=part / part.sum())
        media = CLASSES[c][4]
        k = min(len(por_classe[c]), rng.geometric(1 / media))
        for a in rng.choice(por_classe[c], size=k, replace=False):
            linhas.append((idx, a))
    itens = pd.DataFrame(linhas, columns=["idx", "ativo"])
    itens = itens.merge(teste[["cve", "pub", "t_d", "data_kev"]], left_on="idx", right_index=True)
    itens = itens.merge(inv[["ativo", "classe", "I_media", "I_max", "esforco"]], on="ativo")
    return itens.reset_index(drop=True)


ESTRATEGIAS = ["volume", "cvss", "kev_cvss", "epss", "proposta", "proposta_raiz", "aditiva", "cvss_impacto", "proposta_meta"]


def pontuar(itens_abertos, t, ctx, est_t, p_t, rng, I_col="I_media", pm_t=None):
    it = itens_abertos
    kev_t = it["data_kev"].notna() & (it["data_kev"] <= t)
    nota = est_t.loc[it["idx"], "nota"].values
    p = p_t.loc[it["idx"]].values.copy()
    p[kev_t.values] = 1.0
    I = it[I_col].values
    ep = ctx["epss"][t].reindex(it["cve"]).fillna(0).values if t in ctx["epss"] else np.zeros(len(it))
    nota0 = np.nan_to_num(nota, nan=0.0)
    return {
        "volume": -it["esforco"].values,
        "cvss": nota0,
        "kev_cvss": kev_t.values * 100 + nota0,
        "epss": ep,
        "proposta": p * I,
        "proposta_raiz": np.sqrt(p * I),
        "aditiva": 0.5 * p + 0.5 * I,
        "cvss_impacto": nota0 / 10 * I,
        "proposta_meta": (np.where(kev_t.values, 1.0, pm_t.loc[it["idx"]].values) * I) if pm_t is not None else p * I,
        "proposta_hora": p * I / it["esforco"].values,
        "_desempate": rng.random(len(it)),
    }, p


def simular(teste, ctx, seed, capacidade=0.10, I_col="I_media", fator_e=1.0, estrategias=ESTRATEGIAS):
    rng = np.random.default_rng(seed)
    inv = gerar_inventario(2000, rng)
    if fator_e != 1.0:
        inv["I_media"] = ((inv["c"] + inv["i"] + inv["a"]) / 15 * np.clip(inv["e"] * fator_e, 0, 1))
    itens = gerar_itens(teste, inv, rng)
    lista = ciclos(date(2025, 2, 1), HORIZONTE)
    desempate = rng.random(len(itens))  # mesma chave de desempate para todas as estratégias
    res = {}
    for nome in estrategias:
        aberto = np.ones(len(itens), bool)
        data_fix = np.array([None] * len(itens))
        for t in lista:
            disp = aberto & (itens["t_d"].values <= t)
            if not disp.any():
                continue
            sel = itens[disp]
            sc, _ = pontuar(sel, t, ctx, ctx["estado"][t], ctx["p"][t], rng, I_col, ctx["p_meta"][t])
            ordem = np.lexsort((desempate[sel.index.values], -sc[nome]))
            horas = capacidade * sel["esforco"].sum()
            esf = sel["esforco"].values[ordem]
            cum = np.cumsum(esf)
            escolhidos = sel.index.values[ordem[cum <= horas]]
            aberto[escolhidos] = False
            data_fix[escolhidos] = t
        res[nome] = metricas(itens, data_fix)
    return res, len(itens)


def metricas(itens, data_fix):
    fim = HORIZONTE
    expl = itens["data_kev"].notna() & (itens["data_kev"] <= fim)
    fix = pd.Series(data_fix, index=itens.index)
    corrigido = fix.notna()
    # exposição ponderada: I x dias aberto após a inclusão no KEV, até a correção ou o horizonte
    expo = 0.0
    cob_n = cob_d = 0
    for i in itens.index[expl]:
        k = max(itens.at[i, "data_kev"], itens.at[i, "t_d"])
        f = fix[i] if fix[i] is not None else fim
        expo += itens.at[i, "I_media"] * max(0, (f - k).days)
        if itens.at[i, "data_kev"] > itens.at[i, "t_d"]:
            cob_d += 1
            if fix[i] is not None and fix[i] <= itens.at[i, "data_kev"]:
                cob_n += 1
    efic = (expl & corrigido).sum() / max(1, corrigido.sum())
    return {"exposicao": expo, "cobertura": cob_n / max(1, cob_d), "eficiencia": efic,
            "corrigidos": int(corrigido.sum()), "explorados": int(expl.sum())}

# ----------------------------------------------------------------------------
# Execução
# ----------------------------------------------------------------------------

def main(pasta, saida, n_sementes=30):
    os.makedirs(saida, exist_ok=True)
    base, kev, epss = carregar(pasta)
    out = {}

    tr, est_tr, excl_tr = montar_conjunto(base, TREINO_INI, TREINO_FIM)
    te, est_te, excl_te = montar_conjunto(base, TESTE_INI, TESTE_FIM)
    auditar(tr, est_tr, tr["t_d"])
    auditar(te, est_te, te["t_d"])
    assert tr["t_d"].map(lambda t: t + timedelta(days=365)).max() <= te["t_d"].min(), "rótulo de treino invade o teste"
    out["dados"] = {
        "treino_n": len(tr), "treino_pos": int(tr["y"].sum()), "treino_excl_kev": excl_tr,
        "teste_n": len(te), "teste_pos": int(te["y"].sum()), "teste_excl_kev": excl_te,
        "fonte_treino": est_tr["fonte"].value_counts().to_dict(),
        "fonte_teste": est_te["fonte"].value_counts().to_dict(),
        "kev_versao": len(kev),
    }
    # quanto mudaria se usássemos o vetor final da NVD no teste (risco de vazamento)
    both = te["ana_vet"].fillna("").ne("") & te["rec_vet"].fillna("").ne("") & (te["ana_data"] > te["t_d"])
    out["dados"]["teste_analise_apos_td"] = int((te["ana_data"].isna() | (te["ana_data"] > te["t_d"])).sum())
    out["dados"]["teste_vetor_mudou_apos_td"] = int((te.loc[both, "ana_vet"] != te.loc[both, "rec_vet"]).sum())
    out["dados"]["teste_vetor_comparavel"] = int(both.sum())

    ep_tr = epss_em(epss, tr["cve"], tr["t_d"])
    ep_te = epss_em(epss, te["cve"], te["t_d"])
    out["dados"]["epss_cobertura_treino"] = float(np.mean(~np.isnan(ep_tr)))
    out["dados"]["epss_cobertura_teste"] = float(np.mean(~np.isnan(ep_te)))
    mod = treinar(tr, est_tr, ep_tr)
    y = te["y"].values
    nomes = {"lr_meta": "Regressão logística (metadados)", "hgb_meta": "Gradient boosting (metadados)",
             "lr_epss": "Regressão logística (metadados e EPSS)", "hgb_epss": "Gradient boosting (metadados e EPSS)",
             "epss_cal": "EPSS calibrado"}
    series = {nomes[k]: prever(mod, te, est_te, k, ep_te) for k in nomes}
    series["EPSS em t_d"] = np.nan_to_num(ep_te, nan=0.0)
    series["CVSS base"] = np.nan_to_num(est_te["vet"].map(cvss31_base).astype(float).values, nan=0.0)
    cls = {}
    for nome, sc in series.items():
        p1, r1 = prec_rec_at_k(y, sc, 0.01)
        p5, r5 = prec_rec_at_k(y, sc, 0.05)
        prob = nome not in ("EPSS em t_d", "CVSS base")
        cls[nome] = {"ap": average_precision_score(y, sc), "ap_ic": list(bootstrap_ap(y, sc)),
                     "prec_1": p1, "rev_1": r1, "prec_5": p5, "rev_5": r5,
                     "brier": brier_score_loss(y, sc) if prob else None,
                     "media_p": float(np.mean(sc)) if prob else None}
        prec, rec, _ = precision_recall_curve(y, sc)
        cls[nome]["curva"] = [rec.tolist(), prec.tolist()]
    out["classificador"] = cls
    out["modelo"] = {"final": mod["final"], "final_nome": nomes[mod["final"]],
                     "ap_val": {nomes[k]: v["ap_val"] for k, v in mod["variantes"].items()},
                     "params": {nomes[k]: v["params"] for k, v in mod["variantes"].items()},
                     "n_fit": mod["n_fit"], "n_val": mod["n_val"], "pos_fit": mod["pos_fit"], "pos_val": mod["pos_val"],
                     "prevalencia_teste": float(y.mean())}

    # estados e probabilidades por ciclo (recalculados com dados vigentes em t)
    ctx = {"epss": epss, "estado": {}, "p": {}, "p_meta": {}}
    for t in ciclos(date(2025, 2, 1), HORIZONTE):
        est_t = estado_em(te, t)
        auditar(te[te["t_d"] <= t], est_t[te["t_d"] <= t], t)
        est_t["nota"] = est_t["vet"].map(cvss31_base).astype(float)
        ctx["estado"][t] = est_t
        ep_t = epss_em(epss, te["cve"], [t] * len(te))
        ctx["p"][t] = pd.Series(prever(mod, te, est_t, mod["final"], ep_t), index=te.index)
        ctx["p_meta"][t] = pd.Series(prever(mod, te, est_t, "hgb_meta"), index=te.index)

    cenarios = {"C1": {"capacidade": 0.10}, "C2": {"capacidade": 0.05}, "C3": {"capacidade": 0.20},
                "C4a": {"capacidade": 0.10, "fator_e": 0.8}, "C4b": {"capacidade": 0.10, "fator_e": 1.2},
                "C4c": {"capacidade": 0.10, "I_col": "I_max"}}
    sim = {}
    for nome, kw in cenarios.items():
        estr = ESTRATEGIAS if nome == "C1" else ["volume", "cvss", "kev_cvss", "epss", "proposta"]
        linhas = []
        for sd in range(n_sementes):
            r, nit = simular(te, ctx, RNG_BASE + sd, estrategias=estr, **kw)
            for e, m in r.items():
                linhas.append(dict(m, estrategia=e, semente=sd, itens=nit))
        df = pd.DataFrame(linhas)
        resumo = {}
        for e, g in df.groupby("estrategia"):
            resumo[e] = {}
            for col in ("exposicao", "cobertura", "eficiencia", "corrigidos", "explorados", "itens"):
                v = g[col].values.astype(float)
                ic = 1.96 * v.std(ddof=1) / math.sqrt(len(v))
                resumo[e][col] = [float(v.mean()), float(ic)]
        sim[nome] = resumo
        print("cenário", nome, "ok", flush=True)
    out["simulacao"] = sim

    # comparação de funções de risco em um ciclo real
    t = date(2025, 11, 1)
    rng = np.random.default_rng(RNG_BASE)
    inv = gerar_inventario(2000, rng)
    itens = gerar_itens(te, inv, rng)
    abertos = itens[itens["t_d"] <= t].copy()
    sc, p = pontuar(abertos, t, ctx, ctx["estado"][t], ctx["p"][t], np.random.default_rng(0))
    taus = {}
    for e in ("proposta_raiz", "aditiva", "cvss_impacto", "cvss", "epss"):
        taus[e] = float(kendalltau(sc["proposta"], sc[e]).statistic)
    abertos["p"] = p
    abertos["R"] = p * abertos["I_media"].values
    abertos["nota"] = ctx["estado"][t].loc[abertos["idx"], "nota"].values
    abertos["epss"] = epss[t].reindex(abertos["cve"]).values
    for e in ("proposta", "proposta_raiz", "aditiva", "cvss_impacto"):
        abertos["rank_" + e] = pd.Series(sc[e]).rank(ascending=False, method="min").values
    out["funcoes"] = {"t": str(t), "n_itens": len(abertos), "kendall_vs_produto": taus}
    # exemplos: itens com perfis contrastantes
    ex = []
    cand = abertos.sort_values("R", ascending=False)
    pick = [cand.iloc[0]]
    alto_I_baixo_p = abertos[(abertos["I_media"] >= 0.9) & (abertos["p"] < 0.005)].sort_values("I_media", ascending=False)
    if len(alto_I_baixo_p):
        pick.append(alto_I_baixo_p.iloc[0])
    alto_cvss_baixo_p = abertos[(abertos["nota"] >= 9.8) & (abertos["p"] < 0.01)].sort_values("I_media", ascending=False)
    if len(alto_cvss_baixo_p):
        pick.append(alto_cvss_baixo_p.iloc[0])
    alto_p_baixo_I = abertos[(abertos["p"] >= 0.3) & (abertos["I_media"] <= 0.4)].sort_values("p", ascending=False)
    if len(alto_p_baixo_I):
        pick.append(alto_p_baixo_I.iloc[0])
    kev_t = abertos[abertos["data_kev"].notna() & (abertos["data_kev"] <= t)].sort_values("I_media")
    if len(kev_t):
        pick.append(kev_t.iloc[0])
    for r in pick:
        ex.append({k: (str(r[k]) if k in ("cve", "classe", "data_kev") else float(r[k])) for k in
                   ("cve", "classe", "p", "epss", "nota", "I_media", "R", "rank_proposta", "rank_proposta_raiz", "rank_aditiva", "rank_cvss_impacto", "data_kev")})
    out["funcoes"]["exemplos"] = ex
    # soma: 100 itens de p mínimo vs 1 item KEV em ativo de I=1
    out["funcoes"]["soma_ilustrativa"] = {"produto_100_baixos": 100 * 1e-4 * 1.0, "raiz_100_baixos": 100 * math.sqrt(1e-4),
                                           "produto_1_kev": 1.0, "raiz_1_kev": 1.0}

    json.dump(out, open(os.path.join(saida, "resultados.json"), "w"), ensure_ascii=False, indent=1, default=str)
    print("fim", flush=True)
    return out


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 30)
