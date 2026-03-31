#!/bin/bash
if [ -d "venv" ]; then
    source venv/bin/activate
fi
if [ -f ".env" ]; then
    source .env
fi
echo "Instalando dependencias..."
pip3 install -r requirements.txt
echo "Configurando banco de dados..."
python3 src/setup.py
echo "Migrando bancos principais (Auth, Audit e Market)..."
./migration.sh "${AUTH_DB_DSN}" alembic-auth.ini
./migration.sh "${AUDIT_DB_DSN}" alembic-audit.ini
./migration.sh "${MARKET_DB_DSN}" alembic-market.ini

echo "Migrando banco de dados tenant padrão..."
./migration.sh "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${DEFAULT_USER_DB}"

echo "Iniciando servidor..."
python3 src/app.py

