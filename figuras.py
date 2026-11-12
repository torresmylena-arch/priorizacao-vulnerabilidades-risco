"""Gera as figuras do artigo a partir de resultados.json (tons de cinza, padrão SBC)."""
import json, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({"font.family": "serif", "font.size": 9, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.grid": True, "grid.color": "#dddddd",
                     "grid.linewidth": 0.5})

ESTILOS = {
    "EPSS calibrado": dict(color="black", lw=1.6, ls="-"),
    "Gradient boosting (metadados)": dict(color="#555555", lw=1.2, ls="--"),
    "Regressão logística (metadados)": dict(color="#777777", lw=1.2, ls="-."),
    "CVSS base": dict(color="#999999", lw=1.2, ls=":"),
}
NOMES = {"volume": "Volume", "cvss": "CVSS", "kev_cvss": "KEV e CVSS", "epss": "EPSS",
         "proposta": "$p \\cdot I$", "proposta_hora": "$p \\cdot I / h$ (variante)"}


def curva_pr(r, saida):
    fig, ax = plt.subplots(figsize=(4.6, 2.9))
    for nome, est in ESTILOS.items():
        c = r["classificador"][nome]
        rot = nome.replace("t_d", "$t_d$") + f" (AP = {c['ap']:.3f})"
        ax.plot(c["curva"][0], c["curva"][1], label=rot, **est)
    prev = r["modelo"]["prevalencia_teste"]
    ax.axhline(prev, color="#bbbbbb", lw=0.8)
    ax.text(0.98, prev, f"prevalência = {prev:.3f}", ha="right", va="bottom", fontsize=7, color="#666666")
    ax.set_xlabel("Revocação (cobertura)")
    ax.set_ylabel("Precisão (eficiência)")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.legend(frameon=False, fontsize=7, loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(saida, "fig_pr.pdf"))
    plt.close(fig)


def barras_estrategias(r, saida, cen="C1", extra=None):
    s = dict(r["simulacao"][cen])
    ordem = ["volume", "cvss", "kev_cvss", "epss", "proposta"]
    if extra:
        s["proposta_hora"] = extra[cen]["proposta_hora"]
        ordem.append("proposta_hora")
    fig, axs = plt.subplots(1, 2, figsize=(6.4, 2.5))
    for ax, met, tit, esc in ((axs[0], "exposicao", "Exposição ponderada (I x dias)", 1),
                              (axs[1], "cobertura", "Cobertura antes do KEV (%)", 0.01)):
        vals = [s[e][met][0] / esc for e in ordem]
        ics = [s[e][met][1] / esc for e in ordem]
        cores = ["#c8c8c8"] * 4 + ["#222222", "white"]
        bars = ax.barh(range(len(ordem)), vals, xerr=ics, color=cores[:len(ordem)], edgecolor="#222222",
                       linewidth=0.6, height=0.62, error_kw=dict(lw=0.8, capsize=2))
        if extra:
            bars[-1].set_hatch("////")
        ax.set_yticks(range(len(ordem)))
        ax.set_yticklabels([NOMES[e] for e in ordem] if ax is axs[0] else [])
        ax.invert_yaxis()
        ax.set_title(tit, fontsize=8.5)
        ax.grid(axis="y", visible=False)
        lim = max(v + i for v, i in zip(vals, ics))
        for k, (v, i) in enumerate(zip(vals, ics)):
            txt = f"{v:,.0f}".replace(",", ".") if met == "exposicao" else f"{v:.1f}".replace(".", ",")
            ax.text(v + i + lim * 0.02, k, txt, va="center", fontsize=7)
        ax.set_xlim(0, lim * 1.2)
    fig.tight_layout()
    fig.savefig(os.path.join(saida, "fig_estrategias.pdf"))
    plt.close(fig)


if __name__ == "__main__":
    r = json.load(open(sys.argv[1]))
    curva_pr(r, sys.argv[2])
    extra = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else None
    barras_estrategias(r, sys.argv[2], extra=extra)
    print("figuras ok")
