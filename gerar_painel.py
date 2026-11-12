"""Gera o painel de gestão de risco (painel.html) a partir dos dados do protótipo.

Uso: python gerar_painel.py dados painel_modelo.html painel.html
O painel é um arquivo único, sem dependências externas. As CVEs, o KEV e o EPSS são reais;
o inventário de ativos é sintético (mesma semente da primeira repetição do experimento).
"""
import json, sys
from datetime import date
import numpy as np, pandas as pd
import analise as A

TOPO = 100                      # itens da fila mostrados por ciclo
TOPO_CVE = 50                   # vulnerabilidades mostradas por ciclo na visão agrupada
PREFIXO = {"servidor_exposto": "srv-ext", "servidor_interno": "srv-int", "estacao": "est", "rede": "net"}


def preparar(pasta):
    base, kev, epss = A.carregar(pasta)
    tr, est_tr, _ = A.montar_conjunto(base, A.TREINO_INI, A.TREINO_FIM)
    te, est_te, _ = A.montar_conjunto(base, A.TESTE_INI, A.TESTE_FIM)
    mod = A.treinar(tr, est_tr, A.epss_em(epss, tr["cve"], tr["t_d"]))
    ctx = {"epss": epss, "estado": {}, "p": {}, "p_meta": {}}
    for t in A.ciclos(date(2025, 2, 1), A.HORIZONTE):
        est_t = A.estado_em(te, t)
        A.auditar(te[te["t_d"] <= t], est_t[te["t_d"] <= t], t)
        est_t["nota"] = est_t["vet"].map(A.cvss31_base).astype(float)
        ctx["estado"][t] = est_t
        ep_t = A.epss_em(epss, te["cve"], [t] * len(te))
        ctx["p"][t] = pd.Series(A.prever(mod, te, est_t, mod["final"], ep_t), index=te.index)
        ctx["p_meta"][t] = None
    prod = {r.cve: [r.fab, r.prod, r.ransom == "Known"] for r in kev.itertuples()}
    return te, ctx, mod["final"], prod


def rodar(te, ctx, estrategia, seed=A.RNG_BASE, capacidade=0.10, guardar_fila=False, prod=None):
    """Mesma lógica de analise.simular, registrando o que o painel mostra em cada ciclo."""
    rng = np.random.default_rng(seed)
    inv = A.gerar_inventario(2000, rng)
    itens = A.gerar_itens(te, inv, rng)
    itens = itens.merge(inv[["ativo", "c", "i", "a", "e"]], on="ativo")
    desempate = rng.random(len(itens))
    aberto = np.ones(len(itens), bool)
    serie, filas, grupos = [], {}, {}
    for t in A.ciclos(date(2025, 2, 1), A.HORIZONTE):
        disp = aberto & (itens["t_d"].values <= t)
        if not disp.any():
            continue
        sel = itens[disp]
        sc, p = A.pontuar(sel, t, ctx, ctx["estado"][t], ctx["p"][t], rng, "I_media", None)
        R = p * sel["I_media"].values
        ordem = np.lexsort((desempate[sel.index.values], -sc[estrategia]))
        horas = capacidade * sel["esforco"].sum()
        cabe = np.cumsum(sel["esforco"].values[ordem]) <= horas
        esc = ordem[cabe]
        kev_t = (sel["data_kev"].notna() & (sel["data_kev"] <= t)).values
        serie.append({"t": t.isoformat(), "abertos": int(len(sel)), "risco_aberto": float(R.sum()),
                      "risco_reduzido": float(R[esc].sum()), "corrigidos": int(len(esc)), "horas": float(horas),
                      "kev_abertos": int(kev_t.sum()), "kev_corrigidos": int(kev_t[esc].sum()),
                      "ativos": int(sel["ativo"].nunique())})
        if guardar_fila:
            nota = ctx["estado"][t].loc[sel["idx"], "nota"].values
            ep = ctx["epss"][t].reindex(sel["cve"]).values if t in ctx["epss"] else np.full(len(sel), np.nan)
            linhas = []
            for pos, k in enumerate(ordem[:TOPO], 1):
                r = sel.iloc[k]
                linhas.append([pos, r["cve"], "%s-%04d" % (PREFIXO[r["classe"]], r["ativo"]), r["classe"],
                               int(r["c"]), int(r["i"]), int(r["a"]), float(r["e"]),
                               round(float(p[k]), 5), round(float(r["I_media"]), 3), round(float(R[k]), 5),
                               r["data_kev"].isoformat() if kev_t[k] else None,
                               None if np.isnan(nota[k]) else round(float(nota[k]), 1),
                               None if np.isnan(ep[k]) else round(float(ep[k]), 5),
                               float(r["esforco"]), r["pub"].isoformat(), prod.get(r["cve"]) if kev_t[k] else None])
            filas[t.isoformat()] = linhas
            pos = np.empty(len(sel), int); pos[ordem] = np.arange(1, len(sel) + 1)
            df = pd.DataFrame({"cve": sel["cve"].values, "classe": sel["classe"].values, "pos": pos, "p": p, "R": R,
                               "I": sel["I_media"].values, "h": sel["esforco"].values, "kev": kev_t,
                               "data_kev": sel["data_kev"].values, "nota": nota, "ep": ep, "pub": sel["pub"].values})
            g = df.groupby("cve").agg(pos=("pos", "min"), n=("pos", "size"), p=("p", "first"), Imax=("I", "max"),
                                      Rmax=("R", "max"), Rsum=("R", "sum"), h=("h", "sum"), kev=("kev", "first"),
                                      data_kev=("data_kev", "first"), nota=("nota", "first"), ep=("ep", "first"),
                                      pub=("pub", "first")).sort_values("pos").head(TOPO_CVE)
            cont = df[df["cve"].isin(g.index)].groupby(["cve", "classe"]).size().unstack(fill_value=0)
            lg = []
            for cve, r in g.iterrows():
                lg.append([int(r["pos"]), cve, int(r["n"]), [int(cont.loc[cve].get(c, 0)) for c in PREFIXO],
                           round(float(r["p"]), 5), round(float(r["Imax"]), 3), round(float(r["Rmax"]), 5),
                           round(float(r["Rsum"]), 4), r["data_kev"].isoformat() if r["kev"] else None,
                           None if np.isnan(r["nota"]) else round(float(r["nota"]), 1),
                           None if np.isnan(r["ep"]) else round(float(r["ep"]), 5), round(float(r["h"]), 2),
                           r["pub"].isoformat(), prod.get(cve) if r["kev"] else None])
            grupos[t.isoformat()] = lg
        aberto[sel.index.values[esc]] = False
    return serie, filas, grupos


if __name__ == "__main__":
    pasta, modelo, saida = sys.argv[1:4]
    te, ctx, final, prod = preparar(pasta)
    risco, filas, grupos = rodar(te, ctx, "proposta", guardar_fila=True, prod=prod)
    volume, _, _ = rodar(te, ctx, "volume")
    dados = {"gerado_em": date.today().isoformat(), "variante": final, "semente": A.RNG_BASE,
             "colunas": ["pos", "cve", "ativo", "classe", "c", "i", "a", "e", "p", "I", "R", "kev", "cvss", "epss", "esforco", "pub", "produto"],
             "colunas_cve": ["pos", "cve", "n", "classes", "p", "I", "R", "Rsum", "kev", "cvss", "epss", "esforco", "pub", "produto"],
             "classes": list(PREFIXO), "risco": risco, "filas": filas, "grupos": grupos}
    html = open(modelo, encoding="utf-8").read().replace("/*__DADOS__*/null", json.dumps(dados, ensure_ascii=False, separators=(",", ":")))
    open(saida, "w", encoding="utf-8").write(html)
    u = risco[-1]; v = volume[-1]
    print("ciclos:", len(risco), "| itens na fila em", risco[9]["t"], ":", risco[9]["abertos"])
    print("risco reduzido acumulado: fila por risco %.1f | fila por volume %.1f" % (sum(x["risco_reduzido"] for x in risco), sum(x["risco_reduzido"] for x in volume)))
    print("corrigidos acumulados: risco %d | volume %d" % (sum(x["corrigidos"] for x in risco), sum(x["corrigidos"] for x in volume)))
