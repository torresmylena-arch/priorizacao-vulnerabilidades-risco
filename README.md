# Priorização de vulnerabilidades orientada a risco

Protótipo do Projeto de Aplicação da Pós-Graduação em IA e Cibersegurança (PUCPR Digital).
Autora: Mylena Ferreira Torres.

## O que o protótipo faz

1. Reconstrói, para cada CVE, os atributos como estavam na data de decisão `t_d`
   (primeiro ciclo mensal após a publicação), usando o histórico de alterações da NVD.
2. Treina e compara variantes para estimar a probabilidade de exploração em 365 dias
   (regressão logística, gradient boosting, ambos com e sem EPSS, e EPSS calibrado).
3. Calcula o índice de risco `R = p x I`, com `I` derivado da criticidade (CIA) e da exposição do ativo.
4. Simula um ambiente com 2.000 ativos sintéticos e compara estratégias de priorização
   sob a mesma capacidade de correção (30 sementes por cenário).
5. Compara funções de risco (produto, raiz, soma ponderada, CVSS x impacto) com CVEs reais.

## Arquivos

| Arquivo | Conteúdo |
|---|---|
| `prototipo_priorizacao.ipynb` | Notebook que executa o experimento passo a passo |
| `analise.py` | Código do experimento (carga, ponto no tempo, modelos, simulação) |
| `figuras.py` | Figuras do artigo |
| `coleta/coletor_nvd.js` | Coletor usado no navegador para a API e o histórico da NVD |
| `baixar_dados.py` | Alternativa de coleta por linha de comando (mesmas fontes) |
| `dados/` | Dados compactados usados no artigo (NVD, KEV, EPSS) |
| `saida/resultados.json` | Resultados numéricos reportados no artigo |

## Fontes de dados

- NVD, API 2.0 de CVEs e de histórico de alterações (eventos "New CVE Received", "Initial Analysis" e "CVE Rejected").
- Catálogo KEV da CISA, versão de 03/11/2026.
- EPSS (FIRST), arquivos diários do primeiro dia de cada mês, de fev/2023 a jan/2024 e de fev/2025 a nov/2026.

## Desenho temporal

- Treino: CVEs com identificador de 2023 publicadas em 2023; janelas de rótulo terminam até 01/01/2025.
- Teste: CVEs com identificador de 2025 publicadas de jan a out/2025; decisões a partir de 01/02/2025.
- Rótulo: inclusão no KEV no intervalo `(t_d, t_d + 365]`. CVEs já no KEV em `t_d` saem da avaliação.
- A função `auditar` interrompe a execução se algum atributo tiver data posterior à data de decisão.

## Execução

```
python3 analise.py dados saida 30
python3 figuras.py saida/resultados.json saida
```

Requisitos: Python 3.10 ou superior, numpy, pandas, scipy, scikit-learn e matplotlib.
