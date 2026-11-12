"""Segunda rodada de modelos próprios, com sinais abertos e datados (ver coleta/extrair_sinais.py).

Atributos, todos vigentes na data de decisão t:
  - EPSS em t (logit);
  - histórico do fabricante no KEV: inclusões anteriores a t do mesmo fabricante (e do mesmo produto);
  - provas de conceito públicas no GitHub criadas antes de t;
  - três métricas do vetor CVSS vigente em t (vetor de rede, sem privilégio, sem interação).
Variantes definidas antes da avaliação: S1 (regressão logística: EPSS, histórico, provas de conceito),
S2 (S1 mais CVSS e produto) e S3 (gradient boosting com os atributos de S2). A escolha usa somente a
validação temporal de 2023; o teste de 2025 é avaliado uma única vez.
"""
import json, sys
from datetime import date
import numpy as np
from sklearn.metrics import average_precision_score
import analise as A
from analise import Sinais, atributos_sinais as atributos, VARIANTES_S as VARIANTES

# As definições dos sinais e das variantes ficam em analise.py (seção 3b). Este script reproduz, isolada,
# a escolha na validação e a avaliação única no teste.
# Uso: python modelo_sinais.py dados            (validação)
#      python modelo_sinais.py dados teste      (validação e teste)


if __name__ == "__main__":
    pasta = sys.argv[1]
    etapa = sys.argv[2] if len(sys.argv) > 2 else "validacao"
    base, kev, epss = A.carregar(pasta)
    sin = Sinais(pasta, kev)
    tr, est_tr, _ = A.montar_conjunto(base, A.TREINO_INI, A.TREINO_FIM)
    ep_tr = A.epss_em(epss, tr["cve"], tr["t_d"])
    Xs = atributos(sin, tr, est_tr, ep_tr, tr["t_d"])
    y = tr["y"].values
    fit = (tr["pub"] <= date(2023, 8, 31)).values; val = ~fit
    print("treino:", len(tr), "| positivos ajuste/validação:", int(y[fit].sum()), int(y[val].sum()))
    print("cobertura no treino: fabricante %.1f%% | com histórico no KEV %.1f%% | com prova de conceito %.1f%%" %
          (100 * (Xs[1][:, 4] == 0).mean(), 100 * (Xs[0][:, 1] > 0).mean(), 100 * (Xs[0][:, 2] > 0).mean()))
    print("entre os positivos do treino: com histórico %.0f%% | com prova de conceito %.0f%%" %
          (100 * (Xs[0][y == 1, 1] > 0).mean(), 100 * (Xs[0][y == 1, 2] > 0).mean()))
    ref = average_precision_score(y[val], np.nan_to_num(ep_tr, nan=1e-5)[val])
    print("AP na validação | EPSS: %.4f" % ref)
    escolha = {}
    for nome, (k, fn, grade) in VARIANTES.items():
        melhor = max(((average_precision_score(y[val], fn(g).fit(Xs[k][fit], y[fit]).predict_proba(Xs[k][val])[:, 1]), g) for g in grade))
        escolha[nome] = melhor
        print("AP na validação | %s: %.4f (hiperparâmetro %s)" % (nome, melhor[0], melhor[1]))
    final = max(escolha, key=lambda n: escolha[n][0])
    print("variante escolhida na validação:", final if escolha[final][0] > ref else "EPSS calibrado (nenhuma variante superou)")
    json.dump({"ap_val_epss": ref, "ap_val": {n: v[0] for n, v in escolha.items()}, "hiper": {n: v[1] for n, v in escolha.items()},
               "final": final if escolha[final][0] > ref else "epss_cal"}, open("saida/modelo_sinais_validacao.json", "w"), indent=1)

    if etapa == "teste":
        # avaliação única no teste de 2025: ajuste em jan-ago/2023 e calibração de Platt em set-dez/2023, como nas demais variantes
        te, est_te, _ = A.montar_conjunto(base, A.TESTE_INI, A.TESTE_FIM)
        ep_te = A.epss_em(epss, te["cve"], te["t_d"])
        Xt = atributos(sin, te, est_te, ep_te, te["t_d"])
        yt = te["y"].values
        res = {}
        ref_t = np.nan_to_num(ep_te, nan=0.0)
        linhas = {"EPSS": ref_t}
        for nome, (k, fn, grade) in VARIANTES.items():
            m = fn(escolha[nome][1]).fit(Xs[k][fit], y[fit])
            cal = A.Platt().fit(m.predict_proba(Xs[k][val])[:, 1], y[val])
            linhas[nome] = np.clip(cal(m.predict_proba(Xt[k])[:, 1]), 1e-4, 1.0)
            if nome in ("S1", "S2"):
                coef = m[-1].coef_[0]
                res["coef_" + nome] = [float(c) for c in coef]
        alt = sin.alterada_apos(te["cve"].values, list(te["t_d"]))
        for nome, sc in linhas.items():
            ic = A.bootstrap_ap(yt, sc)
            res[nome] = {"ap": float(average_precision_score(yt, sc)), "ap_ic": [float(ic[0]), float(ic[1])],
                         "rev_1": float(A.prec_rec_at_k(yt, sc, 0.01)[1]), "rev_5": float(A.prec_rec_at_k(yt, sc, 0.05)[1]),
                         "ap_sem_alteradas": float(average_precision_score(yt[~alt], sc[~alt]))}
            print("teste | %-5s AP %.4f (%.4f a %.4f) | revocação no 1%%: %.1f%% | no 5%%: %.1f%% | AP só com registros não alterados após t_d: %.4f" %
                  (nome, res[nome]["ap"], ic[0], ic[1], 100 * res[nome]["rev_1"], 100 * res[nome]["rev_5"], res[nome]["ap_sem_alteradas"]))
        # diferença pareada de AP entre a variante escolhida e o EPSS (bootstrap)
        rng = np.random.default_rng(0); n = len(yt); difs = []
        for _ in range(1000):
            i = rng.integers(0, n, n)
            if yt[i].sum() == 0: continue
            difs.append(average_precision_score(yt[i], linhas[final][i]) - average_precision_score(yt[i], ref_t[i]))
        res["dif_ap_final_menos_epss"] = [float(np.mean(difs)), float(np.percentile(difs, 2.5)), float(np.percentile(difs, 97.5))]
        res["registros_alterados_apos_td"] = float(alt.mean()); res["positivos_teste"] = int(yt.sum()); res["final"] = final
        print("diferença de AP (%s menos EPSS): %.4f (IC 95%%: %.4f a %.4f)" % (final, *res["dif_ap_final_menos_epss"]))
        print("registros da CNA alterados após a decisão: %.1f%% | positivos no teste: %d" % (100 * alt.mean(), yt.sum()))
        print("cobertura no teste: fabricante %.1f%% | histórico %.1f%% | prova de conceito %.1f%% | entre positivos: histórico %.0f%%, prova %.0f%%" %
              (100 * (Xt[1][:, 4] == 0).mean(), 100 * (Xt[0][:, 1] > 0).mean(), 100 * (Xt[0][:, 2] > 0).mean(),
               100 * (Xt[0][yt == 1, 1] > 0).mean(), 100 * (Xt[0][yt == 1, 2] > 0).mean()))
        json.dump(res, open("saida/modelo_sinais_teste.json", "w"), indent=1)
