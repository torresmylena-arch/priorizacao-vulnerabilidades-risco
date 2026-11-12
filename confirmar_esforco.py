"""Confirmação da variante de risco por hora (p x I / esforço).

A variante foi definida depois dos resultados principais (explorar_esforco.py, sementes 0 a 29).
Aqui ela é fixada e reavaliada, sem nenhum ajuste, em 30 inventários novos (sementes 1000 a 1029),
nos cenários de capacidade (inclusive 2% e 1%) e de sensibilidade (exposição, impacto e esforço), junto com duas referências que isolam o papel de cada
componente: p / esforço (mesma probabilidade, sem o impacto do ativo) e EPSS / esforço.
Uso: python confirmar_esforco.py dados saida
"""
import json, math, sys
from datetime import date
import numpy as np, pandas as pd
from sklearn.metrics import brier_score_loss
import analise as A

pasta, saida = sys.argv[1:3]
base, kev, epss = A.carregar(pasta)
tr, est_tr, _ = A.montar_conjunto(base, A.TREINO_INI, A.TREINO_FIM)
te, est_te, _ = A.montar_conjunto(base, A.TESTE_INI, A.TESTE_FIM)
ep_te = A.epss_em(epss, te["cve"], te["t_d"])
mod = A.treinar(tr, est_tr, A.epss_em(epss, tr["cve"], tr["t_d"]), A.carregar_sinais(pasta, kev))
ctx = {"epss": epss, "estado": {}, "p": {}, "p_meta": {}, "p_epss": {}}
for t in A.ciclos(date(2025, 2, 1), A.HORIZONTE):
    est_t = A.estado_em(te, t); est_t["nota"] = est_t["vet"].map(A.cvss31_base).astype(float)
    ctx["estado"][t] = est_t
    ep_t = A.epss_em(epss, te["cve"], [t] * len(te))
    ctx["p"][t] = pd.Series(A.prever(mod, te, est_t, mod["final"], ep_t, [t] * len(te)), index=te.index)
    ctx["p_epss"][t] = pd.Series(A.prever(mod, te, est_t, "epss_cal", ep_t), index=te.index)
    ctx["p_meta"][t] = ctx["p"][t]

# calibração: escore de Brier no teste, no instante da decisão
y = te["y"].values
bruto = np.nan_to_num(np.asarray(ep_te, float), nan=0.0)
calib = A.prever(mod, te, est_te, "epss_cal", ep_te)
final = A.prever(mod, te, est_te, mod["final"], ep_te, te["t_d"])
out = {"brier": {"epss_bruto": float(brier_score_loss(y, bruto)), "epss_calibrado": float(brier_score_loss(y, calib)),
                 "modelo_final": float(brier_score_loss(y, final)), "variante_final": mod["final"],
                 "media_prevista_final": float(final.mean()),
                 "prevalencia": float(brier_score_loss(y, np.full(len(y), y.mean()))),
                 "media_prevista_bruto": float(bruto.mean()), "media_prevista_calibrado": float(calib.mean()), "prevalencia_obs": float(y.mean())}}
print("Brier", {k: (round(v, 6) if isinstance(v, float) else v) for k, v in out["brier"].items()}, flush=True)

ESTR = ["volume", "kev_cvss", "epss", "proposta", "proposta_hora", "p_hora", "epss_hora", "proposta_epss", "proposta_epss_hora"]
inv_original = A.gerar_inventario

def com_esforco(fator):
    def g(n, rng):
        inv = inv_original(n, rng)
        inv.loc[inv["classe"] != "estacao", "esforco"] *= fator
        return inv
    return g

CEN = {"C1": dict(capacidade=0.10), "C2": dict(capacidade=0.05), "C3": dict(capacidade=0.20),
       "C4a": dict(capacidade=0.10, fator_e=0.8), "C4b": dict(capacidade=0.10, fator_e=1.2),
       "C4c": dict(capacidade=0.10, I_col="I_max"),
       "C5a": dict(capacidade=0.10, _esforco=0.5), "C5b": dict(capacidade=0.10, _esforco=2.0),
       "C6a": dict(capacidade=0.02), "C6b": dict(capacidade=0.01)}
out["cenarios"] = {}
for nome, kw in CEN.items():
    kw = dict(kw); f = kw.pop("_esforco", None)
    A.gerar_inventario = com_esforco(f) if f else inv_original
    linhas = []
    for sd in range(30):
        r, n = A.simular(te, ctx, A.RNG_BASE + 1000 + sd, estrategias=ESTR, **kw)
        for e, m in r.items():
            linhas.append(dict(m, estrategia=e, semente=sd))
    df = pd.DataFrame(linhas)
    out["cenarios"][nome] = {e: {c: [float(g[c].mean()), float(1.96 * g[c].std(ddof=1) / math.sqrt(len(g)))]
                                 for c in ("exposicao", "cobertura", "corrigidos")} for e, g in df.groupby("estrategia")}
    pv = df.pivot(index="semente", columns="estrategia", values="exposicao")
    pares = {}
    for a, b in (("p_hora", "proposta_hora"), ("kev_cvss", "proposta_hora"), ("epss", "proposta_hora"), ("epss", "proposta"),
                 ("proposta_epss", "proposta"), ("proposta_epss_hora", "proposta_hora")):
        d = pv[a] - pv[b]
        pares[a + "_menos_" + b] = [float(d.mean()), float(1.96 * d.std(ddof=1) / math.sqrt(len(d)))]
    out["cenarios"][nome]["_diferenca_pareada_exposicao"] = pares
    print(nome, {e: (round(v["exposicao"][0]), round(v["exposicao"][1])) for e, v in out["cenarios"][nome].items() if not e.startswith("_")},
          {k: [round(x) for x in v] for k, v in pares.items()}, flush=True)
A.gerar_inventario = inv_original
json.dump(out, open(saida + "/confirmacao_esforco.json", "w"), indent=1)
