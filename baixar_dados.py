"""Download dos dados públicos do protótipo (somente biblioteca padrão do Python).

Fontes:
  - Catálogo KEV da CISA (JSON atual, com dateAdded de cada CVE)
  - Arquivos diários históricos do EPSS (FIRST), um por ciclo mensal
  - NVD API 2.0: registros de CVE publicados entre 2021 e 2024
  - NVD API 2.0: histórico de alterações (eventos "New CVE Received", "Initial Analysis" e "CVE Rejected")

Uso: python3 baixar_dados.py <pasta_destino> [etapa]
  etapa: kev | epss | cves | historico | tudo (padrão)
O script é retomável: arquivos já baixados são pulados.
"""
import gzip, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timedelta

UA = {"User-Agent": "projeto-aplicacao-pucpr/1.0"}
PAUSA_NVD = 6.5          # limite público da NVD: 5 requisições a cada 30 s
ANOS_CVE = (2021, 2024)  # publicação das CVEs usadas
HIST_INI, HIST_FIM = date(2021, 1, 1), date(2025, 12, 31)
EPSS_INI, EPSS_FIM = date(2024, 2, 1), date(2025, 12, 1)  # ciclos mensais do teste


def baixar(url, destino, tentativas=5):
    if os.path.exists(destino) and os.path.getsize(destino) > 0:
        return "existente"
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    for n in range(tentativas):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                dados = r.read()
            tmp = destino + ".part"
            with open(tmp, "wb") as f:
                f.write(dados)
            os.replace(tmp, destino)
            return "ok"
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "404"
            espera = 10 * (n + 1)
        except Exception:
            espera = 10 * (n + 1)
        time.sleep(espera)
    return "falhou"


def kev(base):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print("kev", baixar(url, os.path.join(base, "kev", "kev.json")), flush=True)


def epss(base):
    d = EPSS_INI
    while d <= EPSS_FIM:
        nome = f"epss_scores-{d.isoformat()}.csv.gz"
        destino = os.path.join(base, "epss", nome)
        st = "falhou"
        for host in ("https://epss.empiricalsecurity.com/", "https://epss.cyentia.com/"):
            st = baixar(host + nome, destino)
            if st in ("ok", "existente"):
                break
        print("epss", d, st, flush=True)
        d = date(d.year + (d.month == 12), d.month % 12 + 1, 1)


def janelas(ini, fim, dias=119):
    a = ini
    while a <= fim:
        b = min(a + timedelta(days=dias), fim)
        yield a, b
        a = b + timedelta(days=1)


def fmt(d, fim=False):
    return d.isoformat() + ("T23:59:59.999" if fim else "T00:00:00.000")


def paginar(endpoint, params, chave_total, pasta, prefixo, tamanho):
    inicio = 0
    while True:
        destino = os.path.join(pasta, f"{prefixo}_{inicio:06d}.json")
        if not os.path.exists(destino):
            q = dict(params, resultsPerPage=tamanho, startIndex=inicio)
            url = endpoint + "?" + urllib.parse.urlencode(q, safe=":")
            st = baixar(url, destino)
            time.sleep(PAUSA_NVD)
            if st != "ok":
                print("  falha", prefixo, inicio, st, flush=True)
                return
        with open(destino, encoding="utf-8") as f:
            total = json.load(f).get(chave_total, 0)
        inicio += tamanho
        if inicio >= total:
            print("  ", prefixo, "total", total, flush=True)
            return


def cves(base):
    ep = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    pasta = os.path.join(base, "nvd_cves")
    for a, b in janelas(date(ANOS_CVE[0], 1, 1), date(ANOS_CVE[1], 12, 31)):
        paginar(ep, {"pubStartDate": fmt(a), "pubEndDate": fmt(b, True)},
                "totalResults", pasta, f"cves_{a.isoformat()}", 2000)


def historico(base):
    ep = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
    pasta = os.path.join(base, "nvd_historico")
    for evento in ("New CVE Received", "Initial Analysis", "CVE Rejected"):
        tag = evento.replace(" ", "_").lower()
        for a, b in janelas(HIST_INI, HIST_FIM):
            paginar(ep, {"changeStartDate": fmt(a), "changeEndDate": fmt(b, True),
                         "eventName": evento},
                    "totalResults", pasta, f"{tag}_{a.isoformat()}", 5000)


if __name__ == "__main__":
    base = sys.argv[1]
    etapa = sys.argv[2] if len(sys.argv) > 2 else "tudo"
    print("início", datetime.now().isoformat(timespec="seconds"), etapa, flush=True)
    for nome, func in (("kev", kev), ("epss", epss), ("cves", cves), ("historico", historico)):
        if etapa in (nome, "tudo"):
            func(base)
    print("fim", datetime.now().isoformat(timespec="seconds"), flush=True)
