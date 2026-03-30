import sqlite3
import os
import db_adapter

_default_db_dir = os.environ.get(
    'DB_DIRECTORY',
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
)
DB_DIRECTORY = _default_db_dir
DB_PATH = os.path.join(DB_DIRECTORY, 'user/finance.db')

# Mutable current DB — can be switched at runtime without restarting
_current_db_path = DB_PATH
_current_db_engine = 'sqlite'

def set_current_db(path: str, engine: str = 'sqlite'):
    """Point all subsequent get_db_connection() calls to a different DB file or DSN."""
    global _current_db_path, _current_db_engine
    _current_db_path = path
    _current_db_engine = engine

def get_current_db_path() -> str:
    return _current_db_path

def get_current_db_engine() -> str:
    return _current_db_engine

def get_db_connection():
    return db_adapter.get_connection(_current_db_engine, _current_db_path)

def _get_alembic_url() -> str:
    if _current_db_engine == 'sqlite':
        return f"sqlite:///{_current_db_path}"
    # Handles postgres DSNs for SQLAlchemy
    dsn = _current_db_path
    if dsn.startswith("postgres://"):
        dsn = dsn.replace("postgres://", "postgresql://", 1)
    if not dsn.startswith("postgresql://") and 'postgres' in _current_db_engine.lower():
        # Fallback if just DSN string is passed without protocol
        dsn = f"postgresql://{dsn}"
    return dsn

def init_db():
    """Initialize or upgrade database schema using Alembic migrations."""
    import alembic.config
    import alembic.command

    alembic_cfg_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'alembic.ini')
    alembic_cfg = alembic.config.Config(alembic_cfg_path)
    
    # Override the SQLAlchemy URL dynamically for the current database target
    alembic_cfg.set_main_option("sqlalchemy.url", _get_alembic_url())
    
    # Prevent Alembic from outputting logs to stdout dynamically if preferred, 
    # but regular upgrade head is fine.
    alembic.command.upgrade(alembic_cfg, "head")

def migrate_db():
    """Apply schema migrations on existing databases."""
    init_db()
    return ["Alembic schema migrations executed"]

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    init_db()
    print("Database up-to-date with Alembic.")

