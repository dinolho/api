import sqlite3
import re
import os
try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None

def upsert_config(conn, table_name: str, key: str, value: str):
    """Cross-database config upsert (INSERT OR REPLACE)."""
    dialect = getattr(conn, 'dialect', 'sqlite')
    if dialect == 'postgres':
        sql = f"""
            INSERT INTO {table_name} (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP) 
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP
        """
        conn.execute(sql, (key, value))
    elif dialect == 'mysql':
        sql = f"""
            INSERT INTO {table_name} (key, value, updated_at) 
            VALUES (?, ?, CURRENT_TIMESTAMP) 
            ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = CURRENT_TIMESTAMP
        """
        conn.execute(sql, (key, value))
    else:
        # SQLite
        sql = f"""
            INSERT OR REPLACE INTO {table_name} (key, value, updated_at) 
            VALUES (?, ?, datetime('now'))
        """
        conn.execute(sql, (key, value))


def translate_sqlite_to_postgres(sql: str) -> str:
    """Translates SQLite specific SQL syntax to PostgreSQL."""
    # Placeholders: ? to %s (Basic implementation, ignores ? inside strings)
    # A more robust regex replaces ? that are not inside quotes.
    # For now, simple replace since we don't have ? inside literal strings mostly.
    
    # Let's count ? and replace them sequentially with %s
    # We use a trick: split and join
    parts = sql.split('?')
    sql_pg = '%s'.join(parts)

    # DataTypes and constraints
    sql_pg = re.sub(r'\bINTEGER PRIMARY KEY AUTOINCREMENT\b', 'SERIAL PRIMARY KEY', sql_pg, flags=re.IGNORECASE)
    
    # Functions
    sql_pg = re.sub(r"\bdatetime\('now',\s*'utc'\)", "CURRENT_TIMESTAMP AT TIME ZONE 'UTC'", sql_pg, flags=re.IGNORECASE)
    sql_pg = re.sub(r"\bdatetime\('now'\)", "CURRENT_TIMESTAMP", sql_pg, flags=re.IGNORECASE)
    
    # Types
    # sqlite TEXT is fine in pg. Wait, sqlite also has REAL, INT.
    
    # SQLite Pragma
    if "PRAGMA journal_mode" in sql_pg or "PRAGMA foreign_keys" in sql_pg or "PRAGMA synchronous" in sql_pg or "PRAGMA busy_timeout" in sql_pg or "PRAGMA temp_store" in sql_pg or "PRAGMA cache_size" in sql_pg:
        # Postgres doesn't use these pragmas
        return "SELECT 1;"

    return sql_pg


class PostgresCursorWrapper:
    def __init__(self, cur):
        self.cur = cur
        self._lastrowid_val = None

    def execute(self, sql, params=()):
        sql_pg = translate_sqlite_to_postgres(sql)
        
        # Emulate lastrowid for Postgres by appending RETURNING id to INSERTs
        match = re.match(r'^\s*insert\s+into\s+([a-zA-Z0-9_]+)', sql_pg, re.IGNORECASE)
        table_name = match.group(1).lower() if match else None
        
        # Exclude tables known to not have an 'id' column or where it's manual
        tables_no_id = ['transaction_tags', 'central_config']
        
        is_insert_with_id = match and table_name not in tables_no_id and ' returning ' not in sql_pg.lower()
        
        if is_insert_with_id:
            sql_pg += " RETURNING id"
            self.cur.execute(sql_pg, params)
            row = self.cur.fetchone()
            if row and 'id' in row:
                self._lastrowid_val = row['id']
            # We don't want to leave the row in the cursor if the caller expects no rows
            return self

        self.cur.execute(sql_pg, params)
        return self

    def executemany(self, sql, params_seq):
        sql_pg = translate_sqlite_to_postgres(sql)
        self.cur.executemany(sql_pg, params_seq)
        return self

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    def close(self):
        self.cur.close()

    @property
    def lastrowid(self):
        return self._lastrowid_val

    def __iter__(self):
        return iter(self.cur)


class PostgresConnectionWrapper:
    def __init__(self, dsn):
        if psycopg is None:
            raise RuntimeError("psycopg is not installed (pip install psycopg[binary])")
        self.conn = psycopg.connect(dsn, row_factory=dict_row)
        self.conn.autocommit = False

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        sql_pg = translate_sqlite_to_postgres(sql)
        cur.execute(sql_pg, params)
        return PostgresCursorWrapper(cur)

    def executemany(self, sql, params_seq):
        cur = self.conn.cursor()
        sql_pg = translate_sqlite_to_postgres(sql)
        cur.executemany(sql_pg, params_seq)
        return PostgresCursorWrapper(cur)
        
    def executescript(self, sql_script):
        # We need to split the script by semicolons, but ignore semicolons inside strings.
        # Simple for now: just translate the whole script and execute
        sql_pg = translate_sqlite_to_postgres(sql_script)
        with self.conn.cursor() as cur:
            cur.execute(sql_pg)

    def cursor(self):
        return PostgresCursorWrapper(self.conn.cursor())

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

    @property
    def row_factory(self):
        return None
    @row_factory.setter
    def row_factory(self, v):
        pass # Ignored since we setup dict_row at connection time


# Main Factory

def get_connection(type_: str, path_or_dsn: str):
    """
    Returns a connection wrapper matching sqlite3 API.
    - type_: 'sqlite' or 'postgres'
    - path_or_dsn: file path (sqlite) or 'postgresql://...' (postgres)
    """
    if type_.lower() == 'postgres':
        conn = PostgresConnectionWrapper(path_or_dsn)
        conn.dialect = 'postgres'
        return conn
    else:
        # Default fallback to sqlite
        os.makedirs(os.path.dirname(os.path.abspath(path_or_dsn)), exist_ok=True)
        conn = sqlite3.connect(path_or_dsn, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-64000")
        return conn

