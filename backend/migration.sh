#!/bin/bash
# migration.sh: Script for running Alembic migrations on a dynamic DSN

if [ -z "$1" ]; then
    echo "Usage: $0 <dsn>"
    echo "Example: $0 postgresql://user:pass@localhost:5432/finance_db"
    echo "         $0 sqlite:////opt/code/dev/etc/finances/data/user/finance.db"
    exit 1
fi

export MIGRATION_DB_URL="$1"

# Automatically translate postgres:// to postgresql:// as required by psycopg/alchemy
if [[ "${MIGRATION_DB_URL}" == postgres://* ]]; then
    export MIGRATION_DB_URL="postgresql://${MIGRATION_DB_URL#postgres://}"
fi

# Ensure we are in the correct directory
cd "$(dirname "$0")"

if [ ! -f "venv/bin/activate" ]; then
    alembic upgrade head
    exit $?
fi

# Run alembic via virtualenv explicitly
./venv/bin/alembic upgrade head
