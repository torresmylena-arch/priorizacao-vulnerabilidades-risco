"""Compara dois indicadores de governança em 30 inventários (sementes 1000 a 1029):
risco reduzido acumulado (soma dos R dos itens corrigidos) e risco residual médio (soma dos R dos itens
abertos ao fim de cada ciclo). Mostra que o risco reduzido, sozinho, favorece quem corrige tarde.
Uso: python indicadores_governanca.py dados saida
"""
import json, math, sys
import numpy as np
import analise as A, gerar_painel as G

pasta, saida = sys.argv[1:3]
te, ctx, final, prod = G.preparar(pasta)
out = {}
for e in ("volume", "kev_cvss", "epss", "proposta", "proposta_hora"):
    red, res, kev = [], [], []
    for sd in range(30):
        s, _, _ = G.rodar(te, ctx, e, seed=A.RNG_BASE + 1000 + sd)
        red.append(sum(x["risco_reduzido"] for x in s))
        res.append(float(np.mean([x["risco_aberto"] - x["risco_reduzido"] for x in s])))
        kev.append(sum(x["kev_abertos"] - x["kev_corrigidos"] for x in s))
    ic = lambda v: [float(np.mean(v)), float(1.96 * np.std(v, ddof=1) / math.sqrt(len(v)))]
    out[e] = {"risco_reduzido_acumulado": ic(red), "risco_residual_medio": ic(res), "itens_kev_abertos_apos_ciclo": ic(kev)}
    print(e, {k: [round(x, 1) for x in v] for k, v in out[e].items()}, flush=True)
json.dump(out, open(saida + "/indicadores_governanca.json", "w"), indent=1)
