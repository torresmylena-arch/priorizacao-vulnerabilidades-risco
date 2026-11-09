"""Análise exploratória posterior: risco reduzido por hora de esforço (p x I / esforço), cenários C1 e C2."""
import json, math, sys
from datetime import date
import numpy as np, pandas as pd
import analise as A

base, kev, epss = A.carregar('dados')
tr, est_tr, _ = A.montar_conjunto(base, A.TREINO_INI, A.TREINO_FIM)
te, est_te, _ = A.montar_conjunto(base, A.TESTE_INI, A.TESTE_FIM)
mod = A.treinar(tr, est_tr, A.epss_em(epss, tr['cve'], tr['t_d']))
ctx = {"epss": epss, "estado": {}, "p": {}, "p_meta": {}}
for t in A.ciclos(date(2025, 2, 1), A.HORIZONTE):
    est_t = A.estado_em(te, t); est_t["nota"] = est_t["vet"].map(A.cvss31_base).astype(float)
    ctx["estado"][t] = est_t
    ep_t = A.epss_em(epss, te["cve"], [t] * len(te))
    ctx["p"][t] = pd.Series(A.prever(mod, te, est_t, mod["final"], ep_t), index=te.index)
    ctx["p_meta"][t] = ctx["p"][t]
out = {}
for cen, cap in (("C1", 0.10), ("C2", 0.05), ("C3", 0.20)):
    linhas = []
    for sd in range(30):
        r, n = A.simular(te, ctx, A.RNG_BASE + sd, capacidade=cap, estrategias=["epss", "proposta", "proposta_hora"])
        for e, m in r.items():
            linhas.append(dict(m, estrategia=e))
    df = pd.DataFrame(linhas)
    out[cen] = {e: {c: [float(g[c].mean()), float(1.96 * g[c].std(ddof=1) / math.sqrt(len(g)))] for c in ("exposicao", "cobertura", "corrigidos")}
                for e, g in df.groupby("estrategia")}
    print(cen, {e: round(v["exposicao"][0]) for e, v in out[cen].items()}, flush=True)
json.dump(out, open("saida/exploratoria_esforco.json", "w"), indent=1)
