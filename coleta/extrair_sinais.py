"""Extrai sinais abertos e datados para o modelo próprio, a partir de dois repositórios públicos:

  1. CVE List V5 (https://github.com/CVEProject/cvelistV5): fabricante e produto informados pela CNA
     (somente o contêiner "cna"; o contêiner "adp" é ignorado porque a CISA o atualiza quando a falha
     entra no KEV, o que vazaria o rótulo) e a data da última alteração feita pela CNA.
  2. PoC-in-GitHub (https://github.com/nomi-sec/PoC-in-GitHub): data de criação de cada repositório
     público com prova de conceito.

Uso: python coleta/extrair_sinais.py <pasta cvelistV5> <pasta PoC-in-GitHub> dados/sinais.json
Leia os arquivos baixados com "python -I", pois são dados de terceiros.
"""
import glob, json, os, sys

cvelist, poc, saida = sys.argv[1:4]
out = {}
for ano in ("2023", "2025"):
    for f in glob.iglob(os.path.join(cvelist, "cves", ano, "*", "CVE-*.json")):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        m = d.get("cveMetadata", {})
        if m.get("state") != "PUBLISHED":
            continue
        cna = d.get("containers", {}).get("cna", {})
        fp = []
        for a in cna.get("affected", []) or []:
            v, p = str(a.get("vendor") or "").strip(), str(a.get("product") or "").strip()
            if (v, p) not in fp:
                fp.append((v[:60], p[:80]))
        out[m["cveId"]] = {"f": fp[:8], "u": (cna.get("providerMetadata", {}).get("dateUpdated") or "")[:10],
                           "pub": (m.get("datePublished") or "")[:10], "poc": []}
        if ano == "2025":
            # situação de correção informada pelo fabricante (usada só no painel, não no modelo)
            fix, ate = [], []
            hexa = set("0123456789abcdef")
            valida = lambda x: (x and x.lower() not in ("*", "unspecified", "n/a", "unknown") and any(ch.isdigit() for ch in x)
                                and not (len(x) >= 12 and set(x.lower()) <= hexa))
            for a in cna.get("affected", []) or []:
                for v in a.get("versions") or []:
                    if v.get("status") != "affected" or str(v.get("versionType") or "").lower() == "git":
                        continue                                 # ignora versões expressas como commits
                    lt, le = str(v.get("lessThan") or "").strip(), str(v.get("lessThanOrEqual") or "").strip()
                    prod = str(a.get("product") or "").strip()[:60]
                    if valida(lt) and (prod, lt[:30]) not in fix:
                        fix.append((prod, lt[:30]))          # "menor que X": X é a primeira versão corrigida
                    elif valida(le) and (prod, le[:30]) not in ate:
                        ate.append((prod, le[:30]))          # "até X": última versão afetada
            texto = lambda k: " ".join(str((cna.get(k) or [{}])[0].get("value") or "").split())[:260]
            aviso = next((r.get("url") for r in cna.get("references", []) or []
                          if {"vendor-advisory", "patch"} & {t.lower() for t in (r.get("tags") or [])}), None)
            c = {}
            if fix: c["v"] = fix[:3]; c["n"] = len(fix)
            elif ate: c["ate"] = ate[:3]; c["n"] = len(ate)
            if texto("solutions"): c["s"] = texto("solutions")
            if texto("workarounds"): c["w"] = texto("workarounds")
            if aviso and str(aviso).startswith("https://"): c["a"] = str(aviso)[:200]
            if c: out[m["cveId"]]["c"] = c
    for f in glob.iglob(os.path.join(poc, ano, "CVE-*.json")):
        cve = os.path.basename(f)[:-5]
        try:
            lst = json.load(open(f, encoding="utf-8"))
        except Exception:
            continue
        if cve in out:
            out[cve]["poc"] = sorted(str(r.get("created_at") or "")[:10] for r in lst if r.get("created_at"))
json.dump(out, open(saida, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
print(len(out), "CVEs |", sum(1 for v in out.values() if v["poc"]), "com prova de conceito |",
      sum(1 for v in out.values() if v["f"] and v["f"][0][0].lower() not in ("", "n/a")), "com fabricante |",
      sum(1 for v in out.values() if "c" in v), "com situação de correção")
