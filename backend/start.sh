#!/bin/bash
if [ -d "venv" ]; then
    source venv/bin/activate
fi
source .env
echo "Instalando dependencias..."
pip3 install -r requirements.txt
echo "Configurando banco de dados..."
python3 src/setup.py
echo "Migrando banco de dados..."
./migration.sh "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${DEFAULT_USER_DB}"
echo "Iniciando servidor..."
python3 src/app.py
