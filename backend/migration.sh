#!/bin/bash
# migration.sh: Script for running Alembic migrations on a dynamic DSN

if [ -z "$1" ]; then
    echo "Usage: $0 <dsn> [alembic_ini_file]"
    echo "Example: $0 postgresql://user:pass@localhost:5432/finance_db"
    echo "         $0 sqlite:////opt/code/dev/etc/finances/data/user/finance.db alembic-auth.ini"
    exit 1
fi

export MIGRATION_DB_URL="$1"
ALEMBIC_CONF="${2:-alembic.ini}"

# Automatically translate postgres:// to postgresql:// as required by psycopg/alchemy
if [[ "${MIGRATION_DB_URL}" == postgres://* ]]; then
    export MIGRATION_DB_URL="postgresql://${MIGRATION_DB_URL#postgres://}"
fi

# Ensure we are in the correct directory
cd "$(dirname "$0")"

if [ ! -f "venv/bin/activate" ]; then
    alembic --config "$ALEMBIC_CONF" upgrade head
    exit $?
fi

# Run alembic via virtualenv explicitly
./venv/bin/alembic --config "$ALEMBIC_CONF" upgrade head
