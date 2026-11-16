"""Verificação do modelo congelado (S1) com as CVEs publicadas em 2024.

O modelo é exatamente o do artigo: regressão logística com EPSS, histórico do fabricante no KEV e provas de
conceito, ajustada com CVEs de jan a ago/2023 e calibrada (Platt) em set a dez/2023. Nada é reajustado aqui.

A população de 2024 vem do registro oficial (CVE List V5): identificador de 2024, publicada em 2024, não
rejeitada e fora do KEV na data de decisão. Antes de avaliar 2024, o script confere em 2025 se essa definição
reproduz a população e o resultado obtidos com as datas da NVD.

Não é um teste prospectivo: os rótulos do treino (CVEs de 2023) só se fecham ao longo de 2024. Serve como
verificação de estabilidade do modelo em outro ano, com mais casos positivos.

EPSS de 2024 (dados/epss/epss_2024.json): arquivos diários do primeiro dia de cada mês, de fev/2024 a jan/2025,
já filtrados para a data de decisão de cada CVE. O arquivo de 01/12/2024 não estava disponível no repositório
do EPSS (erro 403) e foi substituído pelo de 30/11/2024, anterior à data de decisão.
A avaliação de 2024 foi executada uma única vez, em 12/11/2026, com protocolo escrito antes.

Uso: python verificar_2024.py dados            (só a conferência em 2025)
     python verificar_2024.py dados avaliar    (conferência e avaliação de 2024; grava saida/verificacao_2024.json)
"""
import gzip, json, os, sys
from datetime import date, timedelta
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
import analise as A


def conjunto_registro(reg, kev, ano, ini, fim):
    """População definida pelo registro oficial da CVE (mesmas regras de analise.montar_conjunto)."""
    kd = dict(zip(kev["cve"], kev["data_kev"]))
    lin = []
    for c, r in reg.items():
        if not c.startswith("CVE-%d-" % ano) or not r.get("pub"):
            continue
        pub = date.fromisoformat(r["pub"])
        if ini <= pub <= fim:
            lin.append((c, pub))
    df = pd.DataFrame(lin, columns=["cve", "pub"]).sort_values("cve").reset_index(drop=True)
    df["t_d"] = df["pub"].map(A.proximo_ciclo)
    df["data_kev"] = df["cve"].map(kd)
    conhecida = df["data_kev"].notna() & (df["data_kev"] <= df["t_d"])
    excl = int(conhecida.sum())
    df = df[~conhecida].reset_index(drop=True)
    lim = df["t_d"].map(lambda t: t + timedelta(days=365))
    df["y"] = (df["data_kev"].notna() & (df["data_kev"] > df["t_d"]) & (df["data_kev"] <= lim)).astype(int)
    return df, excl


def dif_pareada(y, a, b, n=1000, seed=0):
    rng = np.random.default_rng(seed); m = len(y); difs = []
    for _ in range(n):
        i = rng.integers(0, m, m)
        if y[i].sum() == 0:
            continue
        difs.append(average_precision_score(y[i], a[i]) - average_precision_score(y[i], b[i]))
    return float(average_precision_score(y, a) - average_precision_score(y, b)), [float(np.percentile(difs, 2.5)), float(np.percentile(difs, 97.5))]


def resumo(y, sc):
    ic = A.bootstrap_ap(y, sc)
    k = max(1, int(round(0.01 * len(y))))
    return {"ap": float(average_precision_score(y, sc)), "ap_ic": [float(ic[0]), float(ic[1])],
            "rev_1": float(A.prec_rec_at_k(y, sc, 0.01)[1]), "achados_1": int(round(A.prec_rec_at_k(y, sc, 0.01)[1] * y.sum())),
            "rev_5": float(A.prec_rec_at_k(y, sc, 0.05)[1]), "k_1": k}


if __name__ == "__main__":
    pasta = sys.argv[1]
    avaliar = len(sys.argv) > 2 and sys.argv[2] == "avaliar"
    base, kev, epss = A.carregar(pasta)
    sin = A.Sinais(pasta, kev)

    # modelo congelado: mesmo ajuste e mesma calibração do artigo
    hiper = json.load(open("saida/modelo_sinais_validacao.json"))["hiper"]["S1"]
    tr, est_tr, _ = A.montar_conjunto(base, A.TREINO_INI, A.TREINO_FIM)
    ep_tr = A.epss_em(epss, tr["cve"], tr["t_d"])
    X = A.atributos_sinais(sin, tr, est_tr, ep_tr, tr["t_d"])[0]
    y = tr["y"].values
    fit = (tr["pub"] <= date(2023, 8, 31)).values; val = ~fit
    mod = A._lr_s(hiper).fit(X[fit], y[fit])
    cal = A.Platt().fit(mod.predict_proba(X[val])[:, 1], y[val])
    vazio = lambda df: pd.DataFrame({"vet": [""] * len(df)})

    def pontuar(df, s):
        ep = A.epss_em(epss, df["cve"], df["t_d"])
        Xa = A.atributos_sinais(s, df, vazio(df), ep, df["t_d"])[0]
        return np.nan_to_num(ep, nan=0.0), np.clip(cal(mod.predict_proba(Xa)[:, 1]), 1e-4, 1.0), ep

    out = {"hiper_S1": hiper}
    # 1) conferência em 2025: a população pelo registro reproduz a da NVD?
    te, _, _ = A.montar_conjunto(base, A.TESTE_INI, A.TESTE_FIM)
    r25, _ = conjunto_registro(sin.s, kev, 2025, A.TESTE_INI, A.TESTE_FIM)
    comuns = te.merge(r25, on="cve", suffixes=("_nvd", "_reg"))
    e25, s25, _ = pontuar(r25, sin)
    y25 = r25["y"].values
    out["conferencia_2025"] = {"n_nvd": len(te), "n_registro": len(r25), "em_comum": len(comuns),
                               "mesma_data_decisao": float((comuns["t_d_nvd"] == comuns["t_d_reg"]).mean()),
                               "positivos_nvd": int(te["y"].sum()), "positivos_registro": int(y25.sum()),
                               "EPSS": resumo(y25, e25), "S1": resumo(y25, s25)}
    c = out["conferencia_2025"]
    print("2025 | população NVD %d, registro %d, em comum %d | mesma data de decisão %.1f%% | positivos %d e %d" %
          (c["n_nvd"], c["n_registro"], c["em_comum"], 100 * c["mesma_data_decisao"], c["positivos_nvd"], c["positivos_registro"]))
    print("2025 pelo registro | EPSS AP %.4f | S1 AP %.4f (no artigo, pela NVD: 0,0422 e 0,0943)" % (c["EPSS"]["ap"], c["S1"]["ap"]))

    if avaliar:
        # 2) avaliação única das CVEs de 2024
        reg24 = json.load(gzip.open(os.path.join(pasta, "sinais_2024.json.gz"), "rt", encoding="utf-8"))
        e24 = json.load(open(os.path.join(pasta, "epss", "epss_2024.json")))
        for ds, mp in e24.items():
            epss[date.fromisoformat(ds)] = pd.Series({"CVE-2024-" + k: v for k, v in mp.items()}, dtype=float)
        sin24 = A.Sinais(pasta, kev); sin24.s = reg24
        d24, excl = conjunto_registro(reg24, kev, 2024, date(2024, 1, 1), date(2024, 12, 31))
        ref, s1, ep = pontuar(d24, sin24)
        y24 = d24["y"].values
        alt = sin24.alterada_apos(d24["cve"].values, list(d24["t_d"]))
        dif, ic = dif_pareada(y24, s1, ref)
        out["verificacao_2024"] = {"n": len(d24), "positivos": int(y24.sum()), "prevalencia": float(y24.mean()),
                                   "ja_no_kev_em_td": excl, "sem_epss_em_td": float(np.isnan(ep).mean()),
                                   "EPSS": resumo(y24, ref), "S1": resumo(y24, s1),
                                   "dif_ap": dif, "dif_ap_ic": ic, "alteradas_apos_td": float(alt.mean()),
                                   "ap_sem_alteradas": {"EPSS": float(average_precision_score(y24[~alt], ref[~alt])),
                                                        "S1": float(average_precision_score(y24[~alt], s1[~alt]))},
                                   "positivos_sem_alteradas": int(y24[~alt].sum())}
        v = out["verificacao_2024"]
        print("2024 | %d CVEs, %d positivos (%.2f%%) | sem EPSS na data %.1f%% | registros alterados após a decisão %.1f%%" %
              (v["n"], v["positivos"], 100 * v["prevalencia"], 100 * v["sem_epss_em_td"], 100 * v["alteradas_apos_td"]))
        for nome in ("EPSS", "S1"):
            r = v[nome]
            print("2024 | %-4s AP %.4f (%.4f a %.4f) | revocação no 1%%: %.1f%% (%d de %d) | no 5%%: %.1f%%" %
                  (nome, r["ap"], r["ap_ic"][0], r["ap_ic"][1], 100 * r["rev_1"], r["achados_1"], v["positivos"], 100 * r["rev_5"]))
        print("2024 | diferença de AP (S1 menos EPSS): %.4f (IC 95%%: %.4f a %.4f)" % (dif, ic[0], ic[1]))
        print("2024 | só registros não alterados após a decisão: EPSS %.4f | S1 %.4f (%d positivos)" %
              (v["ap_sem_alteradas"]["EPSS"], v["ap_sem_alteradas"]["S1"], v["positivos_sem_alteradas"]))
        # 3) secundária: 2024 e 2025 juntos (2025 pela população do artigo)
        ep_te = A.epss_em(epss, te["cve"], te["t_d"])
        Xt = A.atributos_sinais(sin, te, vazio(te), ep_te, te["t_d"])[0]
        s_te = np.clip(cal(mod.predict_proba(Xt)[:, 1]), 1e-4, 1.0)
        yj = np.concatenate([y24, te["y"].values]); aj = np.concatenate([s1, s_te]); bj = np.concatenate([ref, np.nan_to_num(ep_te, nan=0.0)])
        dj, icj = dif_pareada(yj, aj, bj)
        out["conjunto_2024_2025"] = {"n": len(yj), "positivos": int(yj.sum()), "EPSS": resumo(yj, bj), "S1": resumo(yj, aj),
                                     "dif_ap": dj, "dif_ap_ic": icj}
        print("2024 e 2025 juntos | %d positivos | EPSS AP %.4f | S1 AP %.4f | diferença %.4f (IC 95%%: %.4f a %.4f)" %
              (int(yj.sum()), out["conjunto_2024_2025"]["EPSS"]["ap"], out["conjunto_2024_2025"]["S1"]["ap"], dj, icj[0], icj[1]))
        json.dump(out, open("saida/verificacao_2024.json", "w"), indent=1)
