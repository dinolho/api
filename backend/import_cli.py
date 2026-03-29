#!/usr/bin/env python3
"""
import_cli.py — CLI de importação automática de extratos bancários.

Fluxo:
  1. (Opcional) Rodar sync_r2.py para baixar arquivos novos do R2
  2. Carregar os atalhos de importação de import_shortcuts.json
  3. Para cada atalho disponível: encontrar arquivos pendentes pelo padrão,
     resolvendo a conta pelo nome, e importar direto no banco SQLite

Uso:
  python import_cli.py --db finance [--no-sync] [--shortcuts-file import_shortcuts.json]
  python import_cli.py --db dolares --no-sync
  python import_cli.py --db finance --shortcut "Nubank Rasj"

Variáveis de ambiente necessárias (via .env):
  ENCRYPTION_KEY   chave AES-GCM (16/24/32 chars)
  FILES_DIRECTORY  pasta com os .csv.enc (padrão: ./files)
  DB_DIRECTORY     pasta com os bancos .db  (padrão: ./data)

  Para o sync (sync_r2.py), também precisam:
  R2_ACCESS_ID / R2_SECRET_KEY / R2_ENDPOINT / R2_BUCKET
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── dotenv ────────────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    _env = Path(__file__).parent / ".env"
    load_dotenv(_env)
except ImportError:
    pass

# ── paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent.resolve()

DB_DIRECTORY = Path(
    os.environ.get("DB_DIRECTORY", _HERE / "data")
)
FILES_DIRECTORY = Path(
    os.environ.get("FILES_DIRECTORY", _HERE / "files")
)
ENCRYPTION_KEY: str = os.environ.get("ENCRYPTION_KEY", "")

SYNC_R2_SCRIPT = Path(
    os.environ.get("SYNC_R2_SCRIPT",
                   _HERE.parent.parent / "email-to-r2" / "sync-bucket.sh")
)
SYNC_R2_PREFIX  = os.environ.get("SYNC_R2_PREFIX", "encrypted/")
SYNC_R2_DEST    = str(FILES_DIRECTORY)

# ── colors ────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"


def _c(color, text): return f"{color}{text}{RESET}"
def ok(msg):    print(_c(GREEN,  f"  ✔  {msg}"))
def warn(msg):  print(_c(YELLOW, f"  ⚠  {msg}"))
def err(msg):   print(_c(RED,    f"  ✖  {msg}"), file=sys.stderr)
def info(msg):  print(_c(CYAN,   f"  →  {msg}"))
def section(title): print(f"\n{BOLD}{title}{RESET}")


# ── crypto ────────────────────────────────────────────────────────────────────
def _decrypt_enc_bytes(raw: bytes) -> bytes:
    """
    Descriptografa IV(12 bytes) || ciphertext+tag  (formato do sync_r2.py).
    Fallback para base64 legado se necessário.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    key_bytes = ENCRYPTION_KEY.encode("utf-8")
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError(
            f"ENCRYPTION_KEY tem {len(key_bytes)} bytes — "
            "deve ter 16, 24 ou 32 caracteres."
        )

    # ── Tentativa 1: IV raw (12 bytes) || ciphertext+tag ──────────────────────
    if len(raw) > 12:
        iv   = raw[:12]
        data = raw[12:]
        try:
            return AESGCM(key_bytes).decrypt(iv, data, None)
        except InvalidTag:
            pass

    # ── Tentativa 2: base64 legado ────────────────────────────────────────────
    import base64
    try:
        decoded = base64.b64decode(raw)
        if len(decoded) > 12:
            return AESGCM(key_bytes).decrypt(decoded[:12], decoded[12:], None)
    except Exception:
        pass

    raise ValueError(
        "Falha ao descriptografar: tag inválida. "
        "Verifique ENCRYPTION_KEY e o formato do arquivo."
    )


# ── db helpers ─────────────────────────────────────────────────────────────────
import sqlite3


def _open_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _ensure_file_imports_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_imports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT NOT NULL,
            md5         TEXT NOT NULL UNIQUE,
            bank        TEXT NOT NULL,
            account_id  INTEGER,
            imported    INTEGER DEFAULT 0,
            duplicates  INTEGER DEFAULT 0,
            invalid     INTEGER DEFAULT 0,
            processed_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()


def _file_md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _list_pending_files(conn: sqlite3.Connection) -> list[dict]:
    """Retorna arquivos .csv.enc em FILES_DIRECTORY ainda não importados neste banco."""
    processed_md5s = {
        r["md5"]
        for r in conn.execute("SELECT md5 FROM file_imports").fetchall()
    }
    result = []
    if FILES_DIRECTORY.is_dir():
        for root, _dirs, fnames in os.walk(FILES_DIRECTORY):
            for fname in sorted(fnames):
                if not fname.endswith(".csv.enc"):
                    continue
                fpath = Path(root) / fname
                rel   = str(fpath.relative_to(FILES_DIRECTORY))
                try:
                    md5  = _file_md5(fpath)
                    size = fpath.stat().st_size
                    mtime = datetime.fromtimestamp(fpath.stat().st_mtime).isoformat()
                except OSError:
                    continue
                result.append({
                    "filename":          rel,
                    "path":              str(fpath),
                    "md5":               md5,
                    "size":              size,
                    "modified_at":       mtime,
                    "already_processed": md5 in processed_md5s,
                })
    return result


def _find_or_create_entity(conn, name, etype, document, bank):
    if not name:
        return None, None
    row = conn.execute(
        "SELECT id, original_entity_id FROM entities WHERE LOWER(name)=LOWER(?)", (name,)
    ).fetchone()
    if row:
        raw_id = row["id"]
        # follow chain
        visited = set()
        current = raw_id
        while current and current not in visited:
            visited.add(current)
            r2 = conn.execute(
                "SELECT original_entity_id FROM entities WHERE id=?", (current,)
            ).fetchone()
            if r2 and r2["original_entity_id"]:
                current = r2["original_entity_id"]
            else:
                break
        canonical_id = current
        return canonical_id, (raw_id if canonical_id != raw_id else None)
    cur = conn.execute(
        "INSERT INTO entities (name, type, document, bank) VALUES (?,?,?,?)",
        (name, etype or "company", document or "", bank or ""),
    )
    return cur.lastrowid, None


# ── parsers import ─────────────────────────────────────────────────────────────
def _import_file(conn: sqlite3.Connection, fpath: Path, fname_rel: str,
                 bank: str, account_id: int, is_credit: bool) -> dict:
    """
    Descriptografa, faz parse e insere transações no banco.
    Retorna dict com: filename, status, imported, duplicates, invalid, error.
    """
    # Adiciona o diretório do backend ao path para importar parsers
    sys.path.insert(0, str(_HERE))
    from parsers import parse_csv_statement  # noqa: PLC0415

    md5 = _file_md5(fpath)

    # Checar se já processado
    existing = conn.execute(
        "SELECT id FROM file_imports WHERE md5=?", (md5,)
    ).fetchone()
    if existing:
        return {"filename": fname_rel, "status": "skipped",
                "reason": "already_processed", "md5": md5,
                "imported": 0, "duplicates": 0, "invalid": 0}

    raw_bytes = fpath.read_bytes()
    try:
        file_bytes = _decrypt_enc_bytes(raw_bytes)
    except ValueError as exc:
        return {"filename": fname_rel, "status": "error", "error": str(exc),
                "imported": 0, "duplicates": 0, "invalid": 0}

    result       = parse_csv_statement(file_bytes, bank=bank)
    transactions = result.get("transactions", [])
    ignored      = result.get("ignored", [])

    count = 0
    dups  = []
    ids = []
    import_meta = json.dumps({
        "source_file":  fname_rel,
        "source_md5":   md5,
        "bank_profile": bank,
        "imported_at":  datetime.now(timezone.utc).isoformat() + "Z",
        "via":          "import_cli",
    }, ensure_ascii=False)

    for t in transactions:
        uid     = t.get("external_uid")
        raw_uid = t.get("raw_external_uid")
        line    = t.get("line")

        if uid:
            dup = conn.execute(
                "SELECT id FROM transactions WHERE external_uid=?", (uid,)
            ).fetchone()
            if dup:
                dups.append(line)
                continue

        entity_id, raw_entity_id = _find_or_create_entity(
            conn,
            t.get("entity_name", ""),
            t.get("entity_type", "company"),
            t.get("entity_document", ""),
            t.get("entity_bank", ""),
        )

        amount   = t["amount"]
        txn_type = t["type"]
        raw_amount = amount if txn_type == "income" else -amount

        if is_credit:
            txn_type = "credit"
            amount   = 0

        conn.execute(
            "INSERT INTO transactions "
            "(account_id, date, description, category, amount, type, is_manual, "
            "external_uid, entity_id, raw_entity_id, raw_external_uid, "
            "raw_description, raw_amount, metadata) "
            "VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?)",
            (account_id, t["date"], t["description"], t["category"],
             amount, txn_type, uid, entity_id, raw_entity_id,
             raw_uid, t["description"], raw_amount, import_meta),
        )
        ids.append(conn.lastrowid)
        if txn_type == "expense":
            conn.execute(
                "UPDATE accounts SET balance = balance - ? WHERE id=?",
                (amount, account_id),
            )
        elif txn_type == "income":
            conn.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id=?",
                (amount, account_id),
            )
        count += 1

    conn.execute(
        "INSERT INTO file_imports (filename, md5, bank, account_id, imported, duplicates, invalid) "
        "VALUES (?,?,?,?,?,?,?)",
        (fname_rel, md5, bank, account_id, count, len(dups), len(ignored)),
    )
    conn.commit()

    return {"filename": fname_rel, "status": "ok", "md5": md5,
            "imported": count, "duplicates": len(dups), "invalid": len(ignored), "ids": ids}


# ── sync step ─────────────────────────────────────────────────────────────────
def run_sync():
    section("📥  Sincronizando arquivos do R2…")

    if not SYNC_R2_SCRIPT.exists():
        warn(f"Script não encontrado: {SYNC_R2_SCRIPT}")
        warn("Pulando sync. Use --no-sync para suprimir este aviso.")
        return False

    cmd = [
        "bash", str(SYNC_R2_SCRIPT),
        "--prefix", SYNC_R2_PREFIX,
        "--dest",   SYNC_R2_DEST,
    ]
    info(f"Executando: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(_HERE))
    if result.returncode == 0:
        ok("Sync concluído.")
        return True
    else:
        err(f"Sync terminou com código {result.returncode}.")
        return False


# ── main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CLI de importação automática de extratos bancários.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python import_cli.py --db finance
  python import_cli.py --db dolares --no-sync
  python import_cli.py --db finance --shortcut "Nubank Rasj"
  python import_cli.py --db finance --list-shortcuts
        """,
    )
    parser.add_argument(
        "--db", required=True,
        help='Nome do banco (ex: "finance" → data/user/finance.db). '
             'Pode ser um caminho absoluto.',
    )
    parser.add_argument(
        "--no-sync", action="store_true",
        help="Pular o passo de sync do R2.",
    )
    parser.add_argument(
        "--shortcuts-file",
        default=str(_HERE / "import_shortcuts.json"),
        help="Caminho para o JSON de atalhos (padrão: import_shortcuts.json).",
    )
    parser.add_argument(
        "--shortcut",
        help='Executar apenas um atalho específico (pelo label exato).',
    )
    parser.add_argument(
        "--list-shortcuts", action="store_true",
        help="Listar os atalhos disponíveis e sair.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Mostrar o que seria importado sem gravar nada.",
    )

    args = parser.parse_args()

    # ── carregar atalhos ───────────────────────────────────────────────────────
    shortcuts_path = Path(args.shortcuts_file)
    if not shortcuts_path.exists():
        err(f"Arquivo de atalhos não encontrado: {shortcuts_path}")
        sys.exit(1)

    with open(shortcuts_path, encoding="utf-8") as f:
        shortcuts = json.load(f)

    if args.list_shortcuts:
        section("📋  Atalhos disponíveis:")
        for s in shortcuts:
            print(f"  {_c(BOLD, s['label'])}")
            print(f"      padrão : {s['pattern']}")
            print(f"      conta  : {s['accountSearch']}")
            print(f"      banco  : {s['bank']}  |  tipo: {s['type']}")
        sys.exit(0)

    if args.shortcut:
        shortcuts = [s for s in shortcuts if s["label"] == args.shortcut]
        if not shortcuts:
            err(f'Atalho "{args.shortcut}" não encontrado. '
                "Use --list-shortcuts para ver os disponíveis.")
            sys.exit(1)

    # ── resolver caminho do banco ──────────────────────────────────────────────
    db_arg = args.db
    if os.path.isabs(db_arg):
        db_path = Path(db_arg)
    else:
        # Aceita "finance", "finance.db", "user/finance", etc.
        if not db_arg.endswith(".db"):
            db_arg += ".db"
        # Tenta primeiro data/user/<nome>, depois data/<nome>
        candidate_user = DB_DIRECTORY / "user" / db_arg
        candidate_root = DB_DIRECTORY / db_arg
        if candidate_user.exists():
            db_path = candidate_user
        elif candidate_root.exists():
            db_path = candidate_root
        else:
            err(f"Banco não encontrado: {candidate_user} nem {candidate_root}")
            sys.exit(1)

    section(f"🗄️   Banco: {db_path}")
    print(f"     {_c(DIM, str(db_path))}")

    # ── sync ───────────────────────────────────────────────────────────────────
    if not args.no_sync:
        run_sync()
    else:
        info("Sync pulado (--no-sync).")

    # ── abrir conexão ──────────────────────────────────────────────────────────
    conn = _open_db(db_path)
    _ensure_file_imports_table(conn)

    # ── listar arquivos ────────────────────────────────────────────────────────
    section("📂  Verificando arquivos na pasta files/…")
    all_files = _list_pending_files(conn)
    pending   = [f for f in all_files if not f["already_processed"]]

    info(f"Total de arquivos .csv.enc : {len(all_files)}")
    info(f"Pendentes (não importados) : {len(pending)}")

    if not pending:
        ok("Nenhum arquivo pendente. Tudo já foi importado!")
        conn.close()
        sys.exit(0)

    # ── carregar contas ────────────────────────────────────────────────────────
    accounts = [
        dict(r)
        for r in conn.execute("SELECT id, name FROM accounts ORDER BY name").fetchall()
    ]

    # ── executar atalhos ───────────────────────────────────────────────────────
    section("⚡  Executando atalhos de importação…")

    total_imported  = 0
    total_dupes     = 0
    total_errors    = 0
    total_skipped   = 0
    shortcuts_run   = 0

    for shortcut in shortcuts:
        label         = shortcut["label"]
        pattern       = shortcut["pattern"]
        account_search = shortcut["accountSearch"]
        bank          = shortcut["bank"]
        type_         = shortcut["type"]
        is_credit     = (type_ == "credit")

        # Filtrar arquivos pendentes pelo padrão
        matching = [
            f for f in pending
            if pattern in f["filename"]
        ]

        print()
        print(f"  {BOLD}▶ {label}{RESET}  {_c(DIM, f'[padrão: {pattern}]')}")

        if not matching:
            warn(f"Nenhum arquivo pendente com padrão '{pattern}'")
            continue

        # Encontrar conta pelo nome (busca parcial, case-insensitive)
        acc = next(
            (a for a in accounts
             if str(account_search).lower() == str(a["id"]).lower()),
            None,
        )
        if not acc:
            err(f"Conta de destino não encontrada: '{account_search}'")
            err(f"  Contas disponíveis: {[a['id'] for a in accounts]}")
            continue

        info(f"  {len(matching)} arquivo(s) para conta '{acc['name']}' (id={acc['id']})")
        shortcuts_run += 1

        for finfo in matching:
            fpath    = Path(finfo["path"])
            fname    = finfo["filename"]

            if args.dry_run:
                print(f"    {_c(DIM, '[dry-run]')} importaria: {fname}")
                continue

            res = _import_file(conn, fpath, fname, bank, acc["id"], is_credit)

            if res["status"] == "ok":
                ok(f"{fname}")
                print("       " + _c(DIM, f"{res['imported']} importadas · {res['duplicates']} duplic. · {res['invalid']} invál. IDS: {res['ids']}"))
                total_imported += res["imported"]
                total_dupes    += res["duplicates"]
            elif res["status"] == "skipped":
                print(f"    {_c(DIM, '↷')} {fname} {_c(DIM, '(já processado)')}")
                total_skipped += 1
            else:
                err(f"{fname}: {res.get('error', '?')}")
                total_errors += 1

    # ── resumo final ───────────────────────────────────────────────────────────
    conn.close()

    section("📊  Resumo")
    print(f"  Atalhos executados : {shortcuts_run}/{len(shortcuts)}")
    if not args.dry_run:
        print(f"  Transações novas   : {_c(GREEN, str(total_imported))}")
        print(f"  Duplicatas         : {_c(YELLOW, str(total_dupes))}")
        print(f"  Já processados     : {_c(DIM, str(total_skipped))}")
        if total_errors:
            print(f"  Erros              : {_c(RED, str(total_errors))}")
    print()


if __name__ == "__main__":
    main()
