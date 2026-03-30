"""
auth_db.py — Multi-tenant auth database for FinancePro
Separate from financial DBs. Stored as auth.db at the app root.
"""
import sqlite3, os, secrets
from werkzeug.security import generate_password_hash, check_password_hash

AUTH_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/auth.db')

AUTH_DB_TYPE = os.environ.get('AUTH_DB_TYPE', 'sqlite')
AUTH_DB_DSN = os.environ.get('AUTH_DB_DSN', AUTH_DB_PATH)

import db_adapter

SCHEMA = '''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS organizations (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    slug         TEXT UNIQUE NOT NULL,
    require_2fa  INTEGER NOT NULL DEFAULT 1,
    created_by   TEXT REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS org_members (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member',
    invited_by TEXT REFERENCES users(id),
    joined_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS org_databases (
    id           TEXT PRIMARY KEY,
    org_id       TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      TEXT REFERENCES users(id) ON DELETE CASCADE,
    db_path      TEXT,
    db_name      TEXT NOT NULL DEFAULT '',
    type         TEXT NOT NULL DEFAULT 'api', -- 'api' (local server), 'external' (remote API), 'browser' (OPFS)
    base_url     TEXT,
    filename     TEXT,
    access_mode  TEXT NOT NULL DEFAULT 'all_members', -- 'all_members', 'restricted'
    created_by   TEXT REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, db_path)
);

CREATE TABLE IF NOT EXISTS db_member_access (
    id               TEXT PRIMARY KEY,
    org_database_id  TEXT NOT NULL REFERENCES org_databases(id) ON DELETE CASCADE,
    user_id          TEXT NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    can_read         INTEGER NOT NULL DEFAULT 1,
    can_write        INTEGER NOT NULL DEFAULT 1,
    granted_by       TEXT REFERENCES users(id),
    granted_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_database_id, user_id)
);

CREATE TABLE IF NOT EXISTS central_config (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TEXT DEFAULT (datetime('now'))
);
'''

def get_auth_conn():
    return db_adapter.get_connection(AUTH_DB_TYPE, AUTH_DB_DSN)

def init_auth_db():
    conn = get_auth_conn()
    conn.executescript(SCHEMA)
    
    # Ad-hoc migrations
    try:
        conn.execute("ALTER TABLE org_databases ADD COLUMN engine TEXT DEFAULT 'sqlite'")
        conn.execute("ALTER TABLE org_databases ADD COLUMN dsn TEXT")
    except Exception:
        pass
    
    conn.commit()
    conn.close()


def uid():
    return secrets.token_hex(8)


# ── Users ─────────────────────────────────────────────────────
def create_user(email: str, password: str, name: str = '') -> dict:
    conn = get_auth_conn()
    user_id = uid()
    pw_hash = generate_password_hash(password)
    conn.execute(
        "INSERT INTO users (id,email,password_hash,name) VALUES (?,?,?,?)",
        (user_id, email.strip().lower(), pw_hash, name.strip())
    )
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row)


def get_user_by_email(email: str):
    conn = get_auth_conn()
    row = conn.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: str):
    conn = get_auth_conn()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def verify_password(user: dict, password: str) -> bool:
    return check_password_hash(user['password_hash'], password)


def update_user_totp(user_id: str, secret: str, enabled: bool):
    conn = get_auth_conn()
    conn.execute(
        "UPDATE users SET totp_secret=?,totp_enabled=?,updated_at=datetime('now') WHERE id=?",
        (secret, 1 if enabled else 0, user_id)
    )
    conn.commit()
    conn.close()


def update_user_password(user_id: str, new_password: str):
    conn = get_auth_conn()
    conn.execute(
        "UPDATE users SET password_hash=?,updated_at=datetime('now') WHERE id=?",
        (generate_password_hash(new_password), user_id)
    )
    conn.commit()
    conn.close()


# ── Organizations ─────────────────────────────────────────────
def _slugify(name: str) -> str:
    import re
    slug = re.sub(r'[^\w\s-]', '', name.lower())
    slug = re.sub(r'[-\s]+', '-', slug).strip('-')
    return slug[:50] or 'org'


def _unique_slug(base: str, conn) -> str:
    slug = base
    i = 2
    while conn.execute("SELECT 1 FROM organizations WHERE slug=?", (slug,)).fetchone():
        slug = f"{base}-{i}"; i += 1
    return slug


def create_org(name: str, owner_id: str, require_2fa: bool = True) -> dict:
    conn = get_auth_conn()
    org_id  = uid()
    mem_id  = uid()
    slug    = _unique_slug(_slugify(name), conn)
    conn.execute(
        "INSERT INTO organizations (id,name,slug,require_2fa,created_by) VALUES (?,?,?,?,?)",
        (org_id, name.strip(), slug, 1 if require_2fa else 0, owner_id)
    )
    conn.execute(
        "INSERT INTO org_members (id,org_id,user_id,role) VALUES (?,?,?,?)",
        (mem_id, org_id, owner_id, 'owner')
    )
    conn.commit()
    row = conn.execute("SELECT * FROM organizations WHERE id=?", (org_id,)).fetchone()
    conn.close()
    return dict(row)


def get_org(org_id: str):
    conn = get_auth_conn()
    row = conn.execute("SELECT * FROM organizations WHERE id=?", (org_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_orgs(user_id: str) -> list:
    conn = get_auth_conn()
    rows = conn.execute("""
        SELECT o.*, m.role, m.joined_at
        FROM organizations o
        JOIN org_members m ON m.org_id=o.id
        WHERE m.user_id=?
        ORDER BY m.joined_at ASC
    """, (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_org(org_id: str, name: str = None, require_2fa: bool = None):
    conn = get_auth_conn()
    if name is not None:
        conn.execute("UPDATE organizations SET name=?,updated_at=datetime('now') WHERE id=?", (name, org_id))
    if require_2fa is not None:
        conn.execute("UPDATE organizations SET require_2fa=?,updated_at=datetime('now') WHERE id=?", (1 if require_2fa else 0, org_id))
    conn.commit()
    conn.close()


# ── Members ───────────────────────────────────────────────────
def get_org_members(org_id: str) -> list:
    conn = get_auth_conn()
    rows = conn.execute("""
        SELECT m.id, m.org_id, m.user_id, m.role, m.joined_at,
               u.email, u.name, u.totp_enabled
        FROM org_members m JOIN users u ON u.id=m.user_id
        WHERE m.org_id=? ORDER BY m.joined_at ASC
    """, (org_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_member_role(org_id: str, user_id: str) -> str | None:
    conn = get_auth_conn()
    row = conn.execute(
        "SELECT role FROM org_members WHERE org_id=? AND user_id=?", (org_id, user_id)
    ).fetchone()
    conn.close()
    return row['role'] if row else None


def add_member(org_id: str, user_id: str, role: str = 'member', invited_by: str = None):
    conn = get_auth_conn()
    existing = conn.execute(
        "SELECT id FROM org_members WHERE org_id=? AND user_id=?", (org_id, user_id)
    ).fetchone()
    if existing:
        conn.close()
        return False
    conn.execute(
        "INSERT INTO org_members (id,org_id,user_id,role,invited_by) VALUES (?,?,?,?,?)",
        (uid(), org_id, user_id, role, invited_by)
    )
    conn.commit()
    conn.close()
    return True


def set_member_role(org_id: str, user_id: str, role: str):
    conn = get_auth_conn()
    conn.execute("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?", (role, org_id, user_id))
    conn.commit()
    conn.close()


def remove_member(org_id: str, user_id: str):
    conn = get_auth_conn()
    conn.execute("DELETE FROM org_members WHERE org_id=? AND user_id=?", (org_id, user_id))
    conn.commit()
    conn.close()


# ── Org Databases ─────────────────────────────────────────────
def get_org_databases(org_id: str) -> list:
    conn = get_auth_conn()
    rows = conn.execute(
        "SELECT * FROM org_databases WHERE org_id=? ORDER BY created_at ASC", (org_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_org_database(org_id: str, db_path: str, db_name: str, created_by: str, access_mode: str = 'all_members', type: str = 'api', base_url: str = '', filename: str = '', user_id: str = None, engine: str = 'sqlite', dsn: str = '') -> dict:
    conn = get_auth_conn()
    existing = conn.execute(
        "SELECT * FROM org_databases WHERE org_id=? AND db_path=?", (org_id, db_path)
    ).fetchone()
    if existing:
        conn.close()
        return dict(existing)
    new_id = uid()
    conn.execute(
        """INSERT INTO org_databases 
           (id, org_id, user_id, db_path, db_name, access_mode, created_by, type, base_url, filename, engine, dsn) 
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (new_id, org_id, user_id or created_by, db_path, db_name, access_mode, created_by, type, base_url, filename, engine, dsn)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM org_databases WHERE id=?", (new_id,)).fetchone()
    conn.close()
    return dict(row)


def remove_org_database(org_database_id: str):
    conn = get_auth_conn()
    conn.execute("DELETE FROM org_databases WHERE id=?", (org_database_id,))
    conn.commit()
    conn.close()


def can_access_db(org_id: str, user_id: str, db_path: str) -> bool:
    """Returns True if user can access the given db_path in the org."""
    conn = get_auth_conn()
    odb = conn.execute(
        "SELECT * FROM org_databases WHERE org_id=? AND db_path=?", (org_id, db_path)
    ).fetchone()
    if not odb:
        conn.close()
        return False
    if odb['access_mode'] == 'all_members':
        mem = conn.execute(
            "SELECT 1 FROM org_members WHERE org_id=? AND user_id=?", (org_id, user_id)
        ).fetchone()
        conn.close()
        return mem is not None
    # restricted
    acc = conn.execute(
        "SELECT can_read FROM db_member_access WHERE org_database_id=? AND user_id=? AND can_read=1",
        (odb['id'], user_id)
    ).fetchone()
    conn.close()
    return acc is not None


def grant_db_access(org_database_id: str, user_id: str, granted_by: str):
    conn = get_auth_conn()
    existing = conn.execute(
        "SELECT id FROM db_member_access WHERE org_database_id=? AND user_id=?", (org_database_id, user_id)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO db_member_access (id,org_database_id,user_id,granted_by) VALUES (?,?,?,?)",
            (uid(), org_database_id, user_id, granted_by)
        )
        conn.commit()
    conn.close()


def revoke_db_access(org_database_id: str, user_id: str):
    conn = get_auth_conn()
    conn.execute("DELETE FROM db_member_access WHERE org_database_id=? AND user_id=?", (org_database_id, user_id))
    conn.commit()
    conn.close()


def get_db_access_list(org_database_id: str) -> list:
    conn = get_auth_conn()
    rows = conn.execute("""
        SELECT a.*, u.email, u.name FROM db_member_access a
        JOIN users u ON u.id=a.user_id
        WHERE a.org_database_id=?
    """, (org_database_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Central Config ──────────────────────────────────────────
def get_central_config(key: str) -> str | None:
    conn = get_auth_conn()
    row = conn.execute("SELECT value FROM central_config WHERE key=?", (key,)).fetchone()
    conn.close()
    return row['value'] if row else None


def set_central_config(key: str, value: str):
    conn = get_auth_conn()
    conn.execute("INSERT OR REPLACE INTO central_config (key, value, updated_at) VALUES (?,?,datetime('now'))", (key, value))
    conn.commit()
    conn.close()


# ── DB Configs (Manual Registries) scope to user/org ─────────
def remove_db_config(id_):
    conn = get_auth_conn()
    conn.execute("DELETE FROM org_databases WHERE id=?", (id_,))
    conn.commit()
    conn.close()


def update_db_config(id_, name, type_, base_url, db_path, filename, engine='sqlite', dsn=''):
    conn = get_auth_conn()
    conn.execute(
        "UPDATE org_databases SET db_name=?,type=?,base_url=?,db_path=?,filename=?,engine=?,dsn=?,updated_at=datetime('now') WHERE id=?",
        (name, type_, base_url, db_path, filename, engine, dsn, id_)
    )
    conn.commit()
    conn.close()


def get_db_configs(org_id: str = None, user_id: str = None) -> list:
    # Now just an alias for listing personal or org-wide databases from the unified table
    conn = get_auth_conn()
    if org_id:
        rows = conn.execute("SELECT * FROM org_databases WHERE org_id=? ORDER BY created_at DESC", (org_id,)).fetchall()
    elif user_id:
        rows = conn.execute("SELECT * FROM org_databases WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
    else:
        rows = []
    conn.close()
    return [dict(r) for r in rows]
