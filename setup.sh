#!/bin/bash
# setup.sh: Roda apenas uma vez apos o 'docker compose up -d' inicial para configurar os bancos
# Ele cria um banco tenant padrao direto no Postgres e roda o migration.sh recem-criado do Alembic

set -e

source .env 

PG_USER=${PG_USER:-$POSTGRES_USER}
PG_PASSWORD=${PG_PASSWORD:-$POSTGRES_PASSWORD}
PG_DB=${PG_DB:-${POSTGRES_DB_USER:-$DEFAULT_USER_DB}}

echo "Iniciando Docker Compose (caso nao esteja rodando)..."
docker compose up -d

echo "Aguardando o container do PostgreSQL iniciar e aceitar conexoes (pode levar alguns segundos)..."
until docker compose exec postgres pg_isready -U ${PG_USER}; do
  sleep 2;
  echo "Aguardando banco...";
done

echo "Banco de dados princial pronto!"

# Cria um banco de dados default financeiro alem do finances_auth (que ja existe via ENV)
echo "Verificando/Criando banco de dados tenant padrao (finances_app)..."
# Usamos o 'grep -q 1' para idempotencia, evitando erro se o banco ja existir
if ! docker compose exec -T -e PGPASSWORD=${PG_PASSWORD} postgres psql -U ${PG_USER} -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = '${PG_DB}'" | grep -q 1; then
  docker compose exec -T -e PGPASSWORD=${PG_PASSWORD} postgres psql -U ${PG_USER} -d postgres -c "CREATE DATABASE ${PG_DB};"
fi

echo "Rodando migrations do Alembic no banco financeiro (via migration.sh)..."
# Roda a tool migration.sh criada anteriormente, conectando no postgres do docker!
docker compose exec -T backend ./migration.sh "postgresql://${PG_USER}:${PG_PASSWORD}@postgres:5432/${PG_DB}"

echo "Bancos configurados com sucesso!"
echo "O sistema esta pronto para uso."
