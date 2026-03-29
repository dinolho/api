# Task: Módulo de Investimentos Completo

## Backend
- [x] database.py — migração campos extras em `investments` (ticker, quantity, indexer, rate, maturity_date, application_date, redemption_term, gross_value, net_value, tax, quota_value, quota_date, notes, institution)
- [x] app.py — CRUD expandido com todos campos + 3 novos endpoints:
  - [x] GET /api/investments/market-data (BCB, AwesomeAPI, BRAPI, CoinGecko)
  - [x] GET /api/investments/insights (recomendações por ativo)
  - [x] GET /api/investments/income-forecast (previsão 1/3/6/12/24 meses)

## Frontend
- [x] Investimentos.jsx — reescrita completa com 4 tabs:
  - [x] Visão Geral — KPIs, donut de alocação, cards por tipo, alertas de vencimento
  - [x] Carteira — cards por ativo com insight expandível, badge de recomendação
  - [x] Previsão de Renda — barras progressivas + tabela detalhada
  - [x] Mercado — CDI/SELIC/IPCA, cotações ações/FIIs, crypto, benchmark vs CDI
  - [x] Formulário dinâmico por tipo (campos diferentes para renda fixa, fundos, ações, FIIs, crypto, CRI/CRA, Tesouro)
