import time, sys
import os   
from dotenv import load_dotenv
load_dotenv() 

try:
    import psycopg
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'psycopg[binary]'])
    import psycopg

import urllib.parse

def _ensure_db(dsn: str, default_conn_dsn: str):
    if not dsn:
        return
    parsed = urllib.parse.urlparse(dsn)
    db_name = parsed.path.lstrip('/')
    if not db_name:
        return
        
    try:
        conn = psycopg.connect(default_conn_dsn, autocommit=True)
        res = conn.execute("SELECT 1 FROM pg_database WHERE datname=%s", (db_name,)).fetchone()
        if not res:
            conn.execute(f'CREATE DATABASE "{db_name}"')
            print(f'Banco de dados {db_name} criado com sucesso.')
        else:
            print(f'Banco de dados {db_name} já existe.')
        conn.close()
    except Exception as e:
        print(f'Erro ao verificar/criar banco {db_name}:', e)

for _ in range(15):
    try:
        # Default connection to the master "postgres" database on the same host
        # using the credentials from DEFAULT_USER_DB_DNS or falling back to simple params
        base_dsn = os.environ.get('DEFAULT_USER_DB_DNS')
        if not base_dsn:
            print("Esperando... DEFAULT_USER_DB_DNS nao configurado.")
            time.sleep(2)
            continue
            
        parsed_base = urllib.parse.urlparse(base_dsn)
        master_dsn = parsed_base._replace(path='/postgres').geturl()
        
        # Test connection first to ensure postgres is up
        with psycopg.connect(master_dsn, connect_timeout=2) as test_conn:
            pass

        print("PostgreSQL está pronto. Configurando bancos...")
        
        # Ensure Default Tenant DB
        _ensure_db(os.environ.get('DEFAULT_USER_DB_DNS'), master_dsn)
        
        # Ensure Auth DB
        _ensure_db(os.environ.get('AUTH_DB_DSN'), master_dsn)
        
        # Ensure Audit DB
        _ensure_db(os.environ.get('AUDIT_DB_DSN'), master_dsn)

        # Ensure Market DB
        _ensure_db(os.environ.get('MARKET_DB_DSN'), master_dsn)

        break
    except Exception as e:
        print('Esperando pelo PostgreSQL ficar pronto...')
        print(e)
        time.sleep(2)