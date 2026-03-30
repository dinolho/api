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

for _ in range(15):
    try:
        print("DEFAULT_USER_DB_DNS: ", os.environ.get('DEFAULT_USER_DB_DNS'))
        conn = psycopg.connect(os.environ.get('DEFAULT_USER_DB_DNS'), autocommit=True)
        res = conn.execute("SELECT 1 FROM pg_database WHERE datname=%s", (os.environ.get('DEFAULT_USER_DB'),)).fetchone()
        if not res:
            conn.execute('CREATE DATABASE ' + os.environ.get('DEFAULT_USER_DB'))
            print(f'Banco de dados {os.environ.get("DEFAULT_USER_DB")} criado com sucesso.')
        else:
            print(f'Banco de dados {os.environ.get("DEFAULT_USER_DB")} já existe.')
        conn.close()
        break
    except Exception as e:
        print('Esperando pelo PostgreSQL ficar pronto...')
        print(e)
        time.sleep(2)