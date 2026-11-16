# Priorização de vulnerabilidades orientada a risco

Protótipo do Projeto de Aplicação da Pós-Graduação em IA e Cibersegurança (PUCPR Digital).
Autora: Mylena Ferreira Torres.

## O que o protótipo faz

1. Reconstrói, para cada CVE, os atributos como estavam na data de decisão `t_d`
   (primeiro ciclo mensal após a publicação), usando o histórico de alterações da NVD.
2. Treina e compara variantes para estimar a probabilidade de exploração em 365 dias, em duas rodadas.
   Na primeira, regressão logística e gradient boosting com metadados da CVE, com e sem EPSS.
   Na segunda, as mesmas técnicas com sinais abertos e datados: EPSS, histórico do fabricante no KEV
   e provas de conceito públicas no GitHub. A escolha usa só a validação temporal de 2023.
3. Calcula o índice de risco `R = p x I`, com `I` derivado da criticidade (CIA) e da exposição do ativo.
4. Simula um ambiente com 2.000 ativos sintéticos e compara estratégias de priorização
   sob a mesma capacidade de correção (30 sementes por cenário).
5. Confirma, em 30 inventários novos, a variante de risco por hora de esforço (`R / h`), definida depois
   dos primeiros resultados, com referências que isolam o papel do modelo, do impacto e do esforço.
6. Compara funções de risco (produto, raiz, soma ponderada, CVSS x impacto) com CVEs reais e
   dois indicadores de governança (risco reduzido e risco residual).
7. Verifica a estabilidade do modelo escolhido, sem reajuste, com as CVEs publicadas em 2024.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `prototipo_priorizacao.ipynb` | Notebook que executa o experimento passo a passo |
| `analise.py` | Código do experimento (carga, ponto no tempo, modelos, simulação) |
| `modelo_sinais.py` | Segunda rodada de modelos, isolada: escolha na validação e avaliação única no teste |
| `verificar_2024.py` | Verificação do modelo congelado com as CVEs de 2024 (execução única) |
| `confirmar_esforco.py` | Rodada de confirmação do risco por hora, com ablações e sensibilidade |
| `indicadores_governanca.py` | Risco reduzido e risco residual por estratégia |
| `explorar_esforco.py` | Risco por hora nos inventários originais (barra hachurada da figura) |
| `gerar_painel.py`, `painel_modelo.html`, `painel.html` | Painel de gestão de risco |
| `figuras.py` | Figuras do artigo |
| `coleta/extrair_sinais.py` | Extrai fabricante, produto e datas das provas de conceito para `dados/sinais.json.gz` |
| `coleta/coletor_nvd.js` | Coletor usado no navegador para a API e o histórico da NVD |
| `baixar_dados.py` | Alternativa de coleta por linha de comando (mesmas fontes) |
| `dados/` | Dados compactados usados no artigo (NVD, KEV, EPSS) |
| `saida/` | Resultados numéricos reportados no artigo (`resultados.json`, `confirmacao_esforco.json`, `indicadores_governanca.json`, `modelo_sinais_teste.json`, `verificacao_2024.json`) |

## Fontes de dados

- NVD, API 2.0 de CVEs e de histórico de alterações (eventos "New CVE Received", "Initial Analysis" e "CVE Rejected").
- Catálogo KEV da CISA, versão de 03/11/2026.
- EPSS (FIRST), arquivos diários do primeiro dia de cada mês, de fev/2023 a jan/2024 e de fev/2025 a nov/2026
  (e de fev/2024 a jan/2025 para a verificação com as CVEs de 2024).
- CVE List V5 (https://github.com/CVEProject/cvelistV5), cópia de 11/11/2026: fabricante e produto informados pela CNA.
  O bloco acrescentado pela CISA (ADP) não é lido, porque é atualizado quando a falha entra no KEV.
- PoC-in-GitHub (https://github.com/nomi-sec/PoC-in-GitHub), cópia de 11/11/2026: data de criação de cada repositório.

## Desenho temporal

- Treino: CVEs com identificador de 2023 publicadas em 2023; janelas de rótulo terminam até 01/01/2025.
- Teste: CVEs com identificador de 2025 publicadas de jan a out/2025; decisões a partir de 01/02/2025.
- Rótulo: inclusão no KEV no intervalo `(t_d, t_d + 365]`. CVEs já no KEV em `t_d` saem da avaliação.
- A função `auditar` interrompe a execução se algum atributo tiver data posterior à data de decisão.
- Sinais abertos: o histórico do fabricante conta só inclusões no KEV anteriores a `t_d`, e as provas de conceito,
  só repositórios criados antes de `t_d`. Fabricante e produto vêm da versão atual do registro da CVE;
  43% dos registros do teste foram alterados depois de `t_d`, e o efeito está medido em `saida/resultados.json`.

## Verificação com as CVEs de 2024

Depois do teste de 2025, o modelo escolhido foi aplicado uma única vez, sem reajuste, às 32.584 CVEs publicadas
em 2024 (63 entraram no KEV em até 365 dias). O protocolo foi escrito antes da execução.

| Conjunto | Positivos | AP do modelo | AP do EPSS | Diferença (IC 95%) | Achados no 1% do topo |
|---|---|---|---|---|---|
| Teste de 2025 | 58 | 0,094 | 0,042 | 0,055 (-0,004 a 0,130) | 21 contra 12 |
| Verificação de 2024 | 63 | 0,051 | 0,048 | 0,004 (-0,054 a 0,064) | 14 contra 9 |
| Os dois anos juntos | 121 | 0,065 | 0,039 | 0,026 (-0,015 a 0,069) | 36 contra 21 |

O ganho de precisão média observado em 2025 não se repetiu em 2024. O modelo não ficou abaixo do EPSS nas medidas
principais e encontrou mais falhas exploradas no topo da fila nos dois anos, mas a vantagem não pode ser tomada
como estável. Restrito aos registros não alterados depois da data de decisão, o modelo teve AP de 0,050 contra
0,052 do EPSS em 2024 (em 2025, 0,156 contra 0,042).

Ressalvas da verificação:
- Não é um teste prospectivo. Os rótulos usados no treino (CVEs de 2023) só se fecham ao longo de 2024.
- A população de 2024 vem do registro oficial (CVE List V5), porque a base da NVD do protótipo cobre 2023 e 2025.
  O script confere antes, em 2025, que essa definição reproduz a população e o resultado obtidos com a NVD
  (30.949 CVEs em comum, mesmos 58 positivos, mesmos valores de AP).
- EPSS de 2024: arquivos diários do primeiro dia de cada mês, de fev/2024 a jan/2025, filtrados para as CVEs de 2024
  na data de decisão de cada uma (`dados/epss/epss_2024.json`). O arquivo de 01/12/2024 não estava disponível
  no repositório do EPSS (erro 403) e foi substituído pelo de 30/11/2024, que é anterior à data de decisão.
  1,8% das CVEs não tinham EPSS na data e entram com o valor mínimo.

Para repetir: `python3 verificar_2024.py dados avaliar` (grava `saida/verificacao_2024.json`).

## Como ver funcionando

- Leitura: abra `prototipo_priorizacao.ipynb` aqui no GitHub. As tabelas e o gráfico já estão gravados.
- Execução sem instalar nada: abra o notebook no Google Colab pelo endereço
  https://colab.research.google.com/github/torresmylena-arch/priorizacao-vulnerabilidades-risco/blob/main/prototipo_priorizacao.ipynb
  e use "Ambiente de execução > Executar tudo".

## Painel de gestão de risco

`painel.html` é a tela do protótipo. Para ver funcionando, abra
https://torresmylena-arch.github.io/priorizacao-vulnerabilidades-risco/painel.html

Também é possível baixar o arquivo e abrir no navegador, sem servidor nem internet.
Ele mostra, para cada ciclo mensal, o risco residual e o reduzido, a fila ordenada pelo risco por hora de esforço,
por vulnerabilidade ou por item, os sinais do modelo que justificam cada posição e a situação de correção
informada pelo fabricante no registro da CVE: versão corrigida, texto de solução ou contorno. Quando o registro
não traz correção, o painel diz isso e sugere um controle compensatório por regra fixa, conforme o vetor de ataque.
As CVEs, o KEV e o EPSS são reais e respeitam a data do ciclo; o inventário de ativos é sintético.

Para gerar de novo: `python gerar_painel.py dados painel_modelo.html painel.html`

## Parâmetros da simulação

Os parâmetros do inventário sintético (participação, requisitos CIA, exposição, esforço de correção
e número médio de ativos afetados por classe) estão no dicionário `CLASSES` de `analise.py`.

## Execução local

```
python3 analise.py dados saida 30            # experimento principal (cerca de 15 minutos)
python3 explorar_esforco.py                  # risco por hora nos inventários originais
python3 confirmar_esforco.py dados saida     # rodada de confirmação (cerca de 20 minutos)
python3 indicadores_governanca.py dados saida
python3 modelo_sinais.py dados teste         # segunda rodada de modelos, isolada
python3 verificar_2024.py dados avaliar      # verificação do modelo congelado com as CVEs de 2024
python3 figuras.py saida/resultados.json saida saida/exploratoria_esforco.json
python3 gerar_painel.py dados painel_modelo.html painel.html
```

Requisitos: Python 3.10 ou superior, numpy, pandas, scipy, scikit-learn e matplotlib.

## Licença e dados

Código sob licença MIT. Os dados vêm de fontes públicas: NVD (NIST), catálogo KEV (CISA) e EPSS (FIRST),
e seguem os termos de uso de cada fonte.
