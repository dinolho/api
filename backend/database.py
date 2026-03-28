import sqlite3
import os

_default_db_dir = os.environ.get(
    'DB_DIRECTORY',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
)
DB_DIRECTORY = _default_db_dir
DB_PATH = os.path.join(DB_DIRECTORY, 'user/finance.db')

# Mutable current DB — can be switched at runtime without restarting
_current_db_path = DB_PATH

def set_current_db(path: str):
    """Point all subsequent get_db_connection() calls to a different DB file."""
    global _current_db_path
    _current_db_path = path

def get_current_db_path() -> str:
    return _current_db_path

def get_db_connection():
    conn = sqlite3.connect(_current_db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        balance INTEGER DEFAULT 0,
        total_transfers INTEGER DEFAULT 0,
        total_balance INTEGER DEFAULT 0,
        currency TEXT DEFAULT 'BRL',
        institution TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
    ''')

    # Entities: companies, people, places that appear in transactions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT DEFAULT 'company',   -- 'person', 'company', 'place', 'other'
        document TEXT,                 -- CPF / CNPJ (raw from Pix)
        bank TEXT,                     -- banco from Pix
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER,
        date TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT,
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        is_manual BOOLEAN DEFAULT 0,
        external_uid TEXT,
        raw_external_uid TEXT,
        entity_id INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        destination_account_id INTEGER,
        FOREIGN KEY (account_id) REFERENCES accounts (id),
        FOREIGN KEY (destination_account_id) REFERENCES accounts (id),
        FOREIGN KEY (entity_id) REFERENCES entities (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS investments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        purchase_price INTEGER,
        current_price INTEGER,
        date TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (account_id) REFERENCES accounts (id)
    )
    ''')

    # Redacted texts to mask sensitive data
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS redacted_texts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT (datetime('now'))
    )
    ''')

    # General system configuration
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT (datetime('now'))
    )
    ''')

    # Default config: redaction disabled by default
    cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('redaction_enabled', '0')")

    conn.commit()
    conn.close()

def migrate_db():
    """Apply schema migrations on existing databases (safe, idempotent)."""
    conn = get_db_connection()
    changes = []

    # Ensure new tables exist
    conn.execute('''CREATE TABLE IF NOT EXISTS redacted_texts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT (datetime('now'))
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY, value TEXT, updated_at TEXT DEFAULT (datetime('now'))
    )''')
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('redaction_enabled', '0')")
    conn.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('invoice_day', '15')")
    conn.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('db_version', '1.0.0')")
    conn.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('credit_invoice_category', 'Fatura Cartão')")

    
    # Standard timestamps for all tables
    all_tables = [
        "accounts", "entities", "transactions", "investments", 
        "categories", "tags", "recurring_expenses", 
        "patrimony_items", "pre_transactions"
    ]
    
    # ── Ensure base tables exist ─────────────────────────────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT DEFAULT 'company',
        document TEXT,
        bank TEXT,
        notes TEXT,
        flags INTEGER DEFAULT 0,
        original_entity_id INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (original_entity_id) REFERENCES entities(id)
    )
    ''')

    # ── Categories ───────────────────────────────────────────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS categories (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT NOT NULL UNIQUE,
        color TEXT DEFAULT '#6366f1',
        icon  TEXT DEFAULT 'tag',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
    ''')

    # Seed default categories if none exist
    _default_categories = [
        ("Alimentação",  "#f59e0b"),
        ("Transporte",   "#06b6d4"),
        ("Moradia",      "#8b5cf6"),
        ("Saúde",        "#22c55e"),
        ("Educação",     "#3b82f6"),
        ("Lazer",        "#ec4899"),
        ("Assinaturas",  "#6366f1"),
        ("Salário",      "#10b981"),
        ("Investimento", "#0ea5e9"),
        ("Consórcios",   "#f97316"),
        ("Boleto",       "#ef4444"),
        ("Outros",       "#a1a1aa"),
        ("Crédito em Conta", "#22c55e"),
        ("Débito em Conta", "#ef4444"),
        ("Estorno", "#0b1913"),
        ("Fatura Cartão", "#2135f1"),
        ("Pix Enviado", "#02dba6"),
        ("Pix Recebido", "#d911b4"),
        ("Saque", "#7f67ec"),
    ]
    for name, color in _default_categories:
        conn.execute(
            "INSERT OR IGNORE INTO categories (name, color) VALUES (?, ?)",
            (name, color)
        )

    # ── Tags ─────────────────────────────────────────────────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS tags (
        id   INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
    ''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS transaction_tags (
        transaction_id INTEGER NOT NULL,
        tag_id         INTEGER NOT NULL,
        PRIMARY KEY (transaction_id, tag_id),
        FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
        FOREIGN KEY (tag_id)         REFERENCES tags(id)         ON DELETE CASCADE
    )
    ''')
    conn.execute('''
    CREATE TABLE IF NOT EXISTS entity_tags (
        entity_id INTEGER NOT NULL,
        tag_id    INTEGER NOT NULL,
        PRIMARY KEY (entity_id, tag_id),
        FOREIGN KEY (entity_id) REFERENCES entities(id)    ON DELETE CASCADE,
        FOREIGN KEY (tag_id)    REFERENCES tags(id)        ON DELETE CASCADE
    )
    ''')

    # ── Recurring expenses ────────────────────────────────────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS recurring_expenses (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        category    TEXT,
        amount      INTEGER NOT NULL,
        type        TEXT DEFAULT 'expense',
        frequency   TEXT NOT NULL DEFAULT 'monthly',
        account_id  INTEGER,
        entity_id   INTEGER,
        next_date   TEXT,
        active      INTEGER DEFAULT 1,
        notes       TEXT,
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (account_id) REFERENCES accounts(id),
        FOREIGN KEY (entity_id)  REFERENCES entities(id)
    )
    ''')

    # ── Patrimony items ───────────────────────────────────────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS patrimony_items (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        name             TEXT NOT NULL,
        type             TEXT NOT NULL DEFAULT 'asset',
        category         TEXT,
        value            INTEGER NOT NULL DEFAULT 0,
        acquisition_date TEXT,
        notes            TEXT,
        created_at       TEXT DEFAULT (datetime('now')),
        updated_at       TEXT DEFAULT (datetime('now'))
    )
    ''')

    # ── Pre-transactions (planned / pending transactions) ─────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS pre_transactions (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        date           TEXT NOT NULL,
        description    TEXT NOT NULL,
        category       TEXT,
        amount         INTEGER NOT NULL,
        type           TEXT DEFAULT 'expense',
        account_id     INTEGER,
        entity_id      INTEGER,
        notes          TEXT,
        status         TEXT DEFAULT 'pending',
        recurring_id   INTEGER,
        transaction_id INTEGER,
        created_at     TEXT DEFAULT (datetime('now')),
        updated_at     TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (account_id)     REFERENCES accounts(id),
        FOREIGN KEY (entity_id)      REFERENCES entities(id),
        FOREIGN KEY (recurring_id)   REFERENCES recurring_expenses(id),
        FOREIGN KEY (transaction_id) REFERENCES transactions(id)
    )
    ''')

    # ── Daily Reconciliation (External balance snapshots) ─────────────────────
    conn.execute('''
    CREATE TABLE IF NOT EXISTS daily_reconciliation (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id       INTEGER NOT NULL,
        date             TEXT NOT NULL,
        external_balance INTEGER,
        notes            TEXT,
        created_at       TEXT DEFAULT (datetime('now')),
        updated_at       TEXT DEFAULT (datetime('now')),
        UNIQUE(account_id, date),
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
    )
    ''')

    # ── Indexes ───────────────────────────────────────────────────────────────
    indexes = [
        ("idx_txn_date",          "transactions(date)"),
        ("idx_txn_account",       "transactions(account_id)"),
        ("idx_txn_entity",        "transactions(entity_id)"),
        ("idx_txn_raw_entity",    "transactions(raw_entity_id)"),
        ("idx_txn_uid",           "transactions(external_uid)"),
        ("idx_txn_conciliation",  "transactions(conciliation_status)"),
        ("idx_txn_type_date",     "transactions(type, date)"),
        ("idx_txn_category",      "transactions(category)"),
        ("idx_txn_flags",         "transactions(flags)"),
        ("idx_txn_recurring",     "transactions(recurring_id)"),
        ("idx_entity_name",       "entities(name)"),
        ("idx_entity_parent",     "entities(original_entity_id)"),
        ("idx_entity_flags",      "entities(flags)"),
        ("idx_txn_tags",          "transaction_tags(tag_id)"),
        ("idx_entity_tags",       "entity_tags(tag_id)"),
    ]
    for idx_name, idx_def in indexes:
        try:
            conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_def}")
            changes.append(f"+idx:{idx_name}")
        except Exception:
            pass


    # ── Migration to Cents ────────────────────────────────────────────────────
    migrated = conn.execute("SELECT value FROM system_config WHERE key='cents_migrated'").fetchone()
    if not migrated:
        # Scale everything by 100 once
        print("Migrando banco de dados para centavos...")
        try:
            conn.execute("UPDATE transactions SET amount = CAST(amount * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE transactions SET raw_amount = CAST(raw_amount * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE accounts SET balance = CAST(balance * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE investments SET amount = CAST(amount * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE patrimony_items SET value = CAST(value * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE recurring_expenses SET amount = CAST(amount * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("UPDATE pre_transactions SET amount = CAST(amount * 100 AS INTEGER)")
        except Exception:
            pass
        try:
            conn.execute("INSERT INTO system_config (key, value) VALUES ('cents_migrated', '1')")
        except Exception:
            pass

    # ── Column migrations ────────────────────────────────────────────────────
    col_migrations = [
        ("transactions", "external_uid",        "TEXT"),
        ("transactions", "entity_id",            "INTEGER"),
        ("transactions", "raw_entity_id",        "INTEGER"),
        ("transactions", "conciliation_status",  "INTEGER DEFAULT 0"),
        ("transactions", "notes",                "TEXT"),
        ("transactions", "flags",                "INTEGER DEFAULT 0"),
        ("transactions", "recurring_id",         "INTEGER"),
        ("transactions", "raw_description",      "TEXT"),
        ("transactions", "raw_amount",           "INTEGER DEFAULT 0"),
        ("transactions", "liquidation_date",     "TEXT"),
        ("transactions", "destination_account_id", "INTEGER"),
        ("transactions", "metadata",             "TEXT"),
        ("transactions", "transaction_ref_id",    "INTEGER"),
        ("entities",     "original_entity_id",   "INTEGER"),
        ("entities",     "flags",                "INTEGER DEFAULT 0"),
        ("entities",     "display_name",         "TEXT"),
        ("entities",     "exclude_from_reports", "INTEGER DEFAULT 0"),
    ]
    
    
    for table in all_tables:
        col_migrations.append((table, "created_at", "TEXT DEFAULT ''"))
        col_migrations.append((table, "updated_at", "TEXT DEFAULT ''"))

    for table, col, coltype in col_migrations:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")
            changes.append(f"+{table}.{col}")
        except Exception:
            pass
            
    # Set default values for newly added columns
    for table in all_tables:
        conn.execute(f"UPDATE {table} SET created_at = datetime('now') WHERE created_at = ''")
        conn.execute(f"UPDATE {table} SET updated_at = datetime('now') WHERE updated_at = ''")


    # ── Triggers for timestamps ───────────────────────────────────────────────
    for table in all_tables:
        # Update trigger
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{table}_updated_at")
        conn.execute(f"""
            CREATE TRIGGER trg_{table}_updated_at
            AFTER UPDATE ON {table}
            FOR EACH ROW
            BEGIN
                UPDATE {table} SET updated_at = datetime('now') WHERE id = OLD.id;
            END;
        """)
        
        # Insert trigger
        conn.execute(f"DROP TRIGGER IF EXISTS trg_{table}_created_at")
        conn.execute(f"""
            CREATE TRIGGER trg_{table}_created_at
            AFTER INSERT ON {table}
            FOR EACH ROW
            WHEN NEW.created_at = '' OR NEW.created_at IS NULL
            BEGIN
                UPDATE {table} SET 
                    created_at = datetime('now'),
                    updated_at = datetime('now')
                WHERE id = NEW.id;
            END;
        """)
        changes.append(f"+trgs:{table}")

    # ── Accounts Total Balance Migration ─────────────────────────────────────
    # Add new columns to accounts
    try:
        conn.execute("ALTER TABLE accounts ADD COLUMN total_transfers INTEGER DEFAULT 0")
        changes.append("+accounts.total_transfers")
    except Exception: pass
    try:
        conn.execute("ALTER TABLE accounts ADD COLUMN total_balance INTEGER DEFAULT 0")
        changes.append("+accounts.total_balance")
    except Exception: pass

    # Initialize values for existing accounts
    conn.execute('''
        UPDATE accounts SET 
        total_transfers = (
            SELECT COALESCE(SUM(raw_amount), 0) 
            FROM transactions 
            WHERE account_id = accounts.id 
            AND type IN ('transfer_in', 'transfer_out')
        )
    ''')
    conn.execute('UPDATE accounts SET total_balance = balance + total_transfers')
    changes.append("init:accounts_totals")

    # ── Triggers for Automated Totals ─────────────────────────────────────────
    
    # 1. Trigger to update total_transfers on transaction INSERT
    conn.execute("DROP TRIGGER IF EXISTS trg_txn_total_transfers_insert")
    conn.execute("""
        CREATE TRIGGER trg_txn_total_transfers_insert
        AFTER INSERT ON transactions
        FOR EACH ROW
        WHEN NEW.type IN ('transfer_in', 'transfer_out')
        BEGIN
            UPDATE accounts 
            SET total_transfers = total_transfers + NEW.raw_amount
            WHERE id = NEW.account_id;
        END;
    """)

    # 2. Trigger to update total_transfers on transaction DELETE
    conn.execute("DROP TRIGGER IF EXISTS trg_txn_total_transfers_delete")
    conn.execute("""
        CREATE TRIGGER trg_txn_total_transfers_delete
        AFTER DELETE ON transactions
        FOR EACH ROW
        WHEN OLD.type IN ('transfer_in', 'transfer_out')
        BEGIN
            UPDATE accounts 
            SET total_transfers = total_transfers - OLD.raw_amount
            WHERE id = OLD.account_id;
        END;
    """)

    # 3. Trigger to update total_transfers on transaction UPDATE
    conn.execute("DROP TRIGGER IF EXISTS trg_txn_total_transfers_update")
    conn.execute("""
        CREATE TRIGGER trg_txn_total_transfers_update
        AFTER UPDATE ON transactions
        FOR EACH ROW
        BEGIN
            -- Subtract OLD if it was a transfer
            UPDATE accounts 
            SET total_transfers = total_transfers - OLD.raw_amount
            WHERE id = OLD.account_id AND OLD.type IN ('transfer_in', 'transfer_out');
            
            -- Add NEW if it is a transfer
            UPDATE accounts 
            SET total_transfers = total_transfers + NEW.raw_amount
            WHERE id = NEW.account_id AND NEW.type IN ('transfer_in', 'transfer_out');
        END;
    """)

    # 4. Trigger to sync total_balance whenever balance or total_transfers changes
    conn.execute("DROP TRIGGER IF EXISTS trg_accounts_sync_total_balance")
    conn.execute("""
        CREATE TRIGGER trg_accounts_sync_total_balance
        AFTER UPDATE OF balance, total_transfers ON accounts
        FOR EACH ROW
        BEGIN
            UPDATE accounts SET total_balance = NEW.balance + NEW.total_transfers WHERE id = NEW.id;
        END;
    """)
    changes.append("+trgs:accounts_sync")

    conn.commit()
    conn.close()
    return changes

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        init_db()
        print("Database initialized.")
    else:
        changes = migrate_db()
        if changes:
            print(f"Migrated: {', '.join(changes)}")
        else:
            print("Database already up-to-date.")
