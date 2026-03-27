"""
Bank-specific CSV import profiles with Nubank pattern parsing and entity extraction.
"""

import csv
import io
import re
import hashlib

# ─── Bank Profiles ──────────────────────────────────────────────────────────
PROFILES = {
    "nubank": {
        "label": "Nubank",
        "date_col": "Data",
        "date_fmt": "%d/%m/%Y",
        "amount_col": "Valor",
        "desc_col": "Descrição",
        "uid_col": "Identificador",
        "cat_col": "",
        "encoding": "utf-8",
        'merge_uid_with_column': 'Descrição',
        'merge_uid_with_column_2': 'Valor',
        "help": "📂 Padrão oficial do Nubank. Procure exportar o CSV diretamente do seu app (pelo menu de conta ou fatura). O sistema processará automaticamente as colunas 'Data', 'Valor' e 'Descrição'. Colunas obrigatórias: Data, Valor e Descrição.",
        "id_cols": ["Data","Identificador", "Valor", "Descrição"]
    },
    "inter": {
        "label": "Banco Inter",
        "date_col": "Data Lan\u00e7amento",
        "date_fmt": "%d/%m/%Y",
        "amount_col": "Valor",
        "desc_col": "Descri\u00e7\u00e3o",
        "uid_col": "",
        "cat_col": "",
        "encoding": "utf-8",
        "delimiter": ";",
        "help": "🏦 Padrão para extratos do Banco Inter. Atenção: no Internet Banking, selecione o período desejado e exporte como CSV. O sistema detectará o delimitador ';' (Ponto-e-vírgula) e colunas como 'Data Lançamento'. Identifica recebedores de PIX através da coluna 'Descrição'.",
        "id_cols": ["Data Lançamento", "Valor", "Descrição","Saldo"]
    },
    "sicoob": {
        "label": "Sicoob",
        "date_col": "Data",
        "date_fmt": "%d/%m/%Y",
        "amount_col": "Valor",
        "desc_col": "Hist\u00f3rico",
        "uid_col": "",
        "cat_col": "",
        "encoding": "latin-1",
        "delimiter": ",",
        "help": "🏪 Padrão Sicoob Cooperativo. Utilize o extrato CSV exportado pelo portal corporativo ou pessoal. Espera as colunas 'Data', 'Valor' e 'Histórico'.",
        "id_cols": ["Data", "Valor", "Histórico"]
    },
    "generic": {
        "label": "Genérico (CSV)",
        "date_col": "",
        "amount_col": "",
        "desc_col": "",
        "uid_col": "",
        "encoding": "utf-8",
        "help": "⚙️ Padrão inteligente e flexível. Utilize este se o seu banco não estiver na lista. O sistema tentará mapear automaticamente campos como 'Date', 'Amount', 'Value' e 'Description'. Funciona bem com a maioria dos bancos brasileiros que seguem o padrão CSV padrão.",
        "id_cols": ["Data", "Valor", "Descrição"]
    },
    "custom": {
        "label": "Personalizado (CSV)",
        "date_col": "",
        "amount_col": "",
        "desc_col": "",
        "uid_col": "",
        "encoding": "utf-8",
    },
}

def get_profiles():
    return [{"id": k, "label": v["label"]} for k, v in PROFILES.items()]

def get_csv_preview(file_bytes):
    """Detect encoding, delimiter and return first 5 rows and headers."""
    content = None
    for enc in ["utf-8", "latin-1", "cp1252"]:
        try:
            content = file_bytes.decode(enc)
            break
        except Exception:
            continue
    if not content:
        return {"error": "Could not decode file"}
    
    if content.startswith("\ufeff"): content = content[1:]
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if not lines: return {"error": "Empty file"}
    
    # Simple delimiter detection on the first meaningful line
    delims = [",", ";", "\t", "|"]
    best_d = ","
    best_count = 0
    for d in delims:
        count = lines[0].count(d)
        if count > best_count:
            best_count = count
            best_d = d
    
    reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter=best_d)
    headers = [h for h in (reader.fieldnames or []) if h]
    rows = []
    for i, row in enumerate(reader):
        rows.append(row)
        if i >= 4: break
        
    return {"headers": headers, "rows": rows, "delimiter": best_d}

# ─── Nubank Description Patterns ─────────────────────────────────────────────
#
# Each entry: (regex_pattern, category, entity_type_hint)
# Groups named 'entity' will be extracted as the linked entity name.
#
_NU_PATTERNS = [
    # Pix recebido
    (
        r"Transferência recebida pelo Pix\s*-\s*(?P<entity>[^-]+?)\s*-\s*(?P<document>[\d.•*/-]+)\s*-\s*(?P<bank>.+)",
        "Pix Recebido", "person"
    ),
    # Pix enviado
    (
        r"Transferência enviada pelo Pix\s*-\s*(?P<entity>[^-]+?)\s*-\s*(?P<document>[\d.•*/-]+)\s*-\s*(?P<bank>.+)",
        "Pix Enviado", "company"
    ),
    # Pagamento de boleto
    (
        r"Pagamento de boleto efetuado\s*-\s*(?P<entity>.+)",
        "Boleto", "company"
    ),
    # Compra no débito via NuPay
    (
        r"Compra no débito via NuPay\s*-\s*(?P<entity>.+)",
        "Alimentação", "company"
    ),
    # Compra no débito
    (
        r"Compra no débito\s*-\s*(?P<entity>.+)",
        "Compras", "company"
    ),
    # Estorno de saque
    (r"Estorno\s*-\s*(?P<entity>Saque.*)", "Estorno", "other"),
    # Saque
    (r"^Saque$", "Saque", "other"),
    # Pagamento de fatura
    (r"^Pagamento de fatura$", "Fatura Cartão", "other"),
    # Crédito em conta
    (r"^Crédito em conta$", "Crédito em Conta", "other"),
    # Débito em conta
    (r"^Débito em conta$", "Débito em Conta", "other"),
    # Transferência NuInvest
    (r"Transferência de saldo NuInvest", "Investimento", "other"),
]

# ─── Inter Bank Description Patterns ──────────────────────────────────────────
#
# Inter CSV Descri\u00e7\u00e3o column format:
#   TYPE_LABEL: "QUOTED_CONTENT"
# or just:
#   TYPE_LABEL
# Pix lines have: Cp :CPF_DIGITS-ENTITY_NAME inside the quotes
#
_INTER_PATTERNS = [
    # Pix recebido / Pix enviado — extract CPF + name from "Cp :CPFDIGITS-NAME"
    (
        r"^Pix recebido\s*:\s*\"Cp\s*:(?P<cpf>\d+)\s*-\s*(?P<entity>.+?)\"\s*$",
        "Pix Recebido", "income", "person"
    ),
    (
        r"^Pix enviado\s*:\s*\"Cp\s*:(?P<cpf>\d+)\s*-\s*(?P<entity>.+?)\"\s*$",
        "Pix Enviado", "expense", "person"
    ),
    # Pix gen\u00e9rico sem CPF
    (
        r"^Pix recebido\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Pix Recebido", "income", "company"
    ),
    (
        r"^Pix enviado\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Pix Enviado", "expense", "company"
    ),
    # Recebimento de proventos (sal\u00e1rio / dividendos)
    (
        r"^Recebimento de proventos\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Sal\u00e1rio", "income", "company"
    ),
    # Pagamento de T\u00edtulo (boleto)
    (
        r"^Pagamento de T[i\u00ed]tulo.*?:\s*\"(?P<entity>.+?)\"\s*$",
        "Boleto", "expense", "company"
    ),
    # Pagamento efetuado
    (
        r"^Pagamento efetuado\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Boleto", "expense", "company"
    ),
    # Aplica\u00e7\u00e3o / Resgate (investimento)
    (
        r"^Aplica[c\u00e7][a\u00e3]o\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Investimento", "expense", "company"
    ),
    (
        r"^Resgate\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Investimento", "income", "company"
    ),
    # D\u00e9bito autom\u00e1tico (sem nome limpo — guarda n\u00famero do doc)
    (
        r"^D[e\u00e9]bito autom[a\u00e1]tico\s*:\s*\"(?P<entity>.*)\"\s*$",
        "Boleto", "expense", "company"
    ),
    # Saque Banco 24H
    (
        r"^SAQUE BANCO 24H\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Saque", "expense", "other"
    ),
    # Transfer\u00eancia
    (
        r"^Transfer[e\u00ea]ncia\s*:\s*\"(?P<entity>.+?)\"\s*$",
        "Outros", "expense", "company"
    ),
    # Qualquer outra linha com "TYPE: \"ENTITY\""
    (
        r"^(?P<label>[^:\"]+?)\s*:\s*\"(?P<entity>.+?)\"\s*$",
        None, None, "company"
    ),
]

def parse_inter_description(description, amount_sign=1):
    """
    Parse a Banco Inter description and return category, entity info.
    amount_sign: +1 for credit (income), -1 for debit (expense)
    """
    desc = description.strip()
    for pattern, default_cat, default_type_hint, entity_type_hint in _INTER_PATTERNS:
        m = re.match(pattern, desc, re.IGNORECASE)
        if m:
            gd = m.groupdict()
            entity_raw = gd.get("entity", "").strip()
            cpf        = gd.get("cpf", "").strip()
            label      = gd.get("label", "").strip()

            # Clean entity name
            entity_name = entity_raw.title().strip()
            # Remove CPF/CNPJ artifacts sometimes left
            entity_name = re.sub(r'\s*(\d{3}\.\d{3}|\d{14}).*$', '', entity_name).strip()

            # If this was the generic catch-all "TYPE: \"ENTITY\"" pattern use label for category
            category = default_cat
            if category is None:
                label_lower = label.lower()
                category = _guess_category_from_entity(entity_name) or _guess_category_generic(label_lower) or "Outros"

            # Refine category by known entity keywords
            guessed = _guess_category_from_entity(entity_name)
            if guessed:
                category = guessed

            return {
                "category":        category,
                "entity_name":     entity_name,
                "entity_type":     entity_type_hint,
                "entity_document": cpf,
                "entity_bank":     "Banco Inter",
            }

    # Fallback
    return {
        "category":        _guess_category_generic(desc),
        "entity_name":     "",
        "entity_type":     "other",
        "entity_document": "",
        "entity_bank":     "",
    }

# Category overrides based on known entity keywords
_ENTITY_CATEGORY_MAP = {
    "netflix": "Assinaturas",
    "spotify": "Assinaturas",
    "amazon": "Assinaturas",
    "prime": "Assinaturas",
    "apple": "Assinaturas",
    "disney": "Assinaturas",
    "google": "Assinaturas",
    "youtube": "Assinaturas",
    "ifood": "Alimentação",
    "rappi": "Alimentação",
    "uber eats": "Alimentação",
    "mcdonalds": "Alimentação",
    "burger": "Alimentação",
    "restaurante": "Alimentação",
    "uber": "Transporte",
    "99pop": "Transporte",
    "cabify": "Transporte",
    "posto": "Transporte",
    "shell": "Transporte",
    "farmácia": "Saúde",
    "drogaria": "Saúde",
    "droga": "Saúde",
    "hospital": "Saúde",
    "plano de saúde": "Saúde",
    "unimed": "Saúde",
    "amazon prime": "Assinaturas",
    "condomínio": "Moradia",
    "aluguel": "Moradia",
    "enel": "Moradia",
    "vivo": "Moradia",
    "claro": "Moradia",
    "tim": "Moradia",
    "escola": "Educação",
    "faculdade": "Educação",
    "consórcio": "Consórcios",
    "consorcio": "Consórcios",
    "consorcadora": "Consórcios",
}

def _guess_category_from_entity(entity_name):
    if not entity_name:
        return None
    lower = entity_name.lower()
    for kw, cat in _ENTITY_CATEGORY_MAP.items():
        if kw in lower:
            return cat
    return None

def parse_nubank_description(description):
    """
    Parse a Nubank description string and return:
        category, entity_name, entity_type, entity_document, entity_bank
    """
    desc = description.strip()
    for pattern, default_category, entity_type_hint in _NU_PATTERNS:
        m = re.match(pattern, desc, re.IGNORECASE)
        if m:
            gd = m.groupdict()
            entity_name = gd.get("entity", "").strip().title()
            # Remove trailing bank code artifacts like "(0077)"
            entity_name = re.sub(r'\s*\(\d+\)\s*$', '', entity_name).strip()
            document = gd.get("document", "").strip()
            bank_raw = gd.get("bank", "").strip()
            # Extract just the bank name from "BANCO INTER (0077) Agência: 1 Conta: ..."
            bank_match = re.match(r'^(.+?)\s*\(\d+\)', bank_raw)
            bank = bank_match.group(1).strip().title() if bank_match else bank_raw.split()[0].title() if bank_raw else ""

            # Refine category from entity name
            category = _guess_category_from_entity(entity_name) or default_category

            return {
                "category": category,
                "entity_name": entity_name,
                "entity_type": entity_type_hint,
                "entity_document": document,
                "entity_bank": f"{bank} from nubank",
            }

    # Fallback: generic category guess
    return {
        "category": _guess_category_generic(desc),
        "entity_name": "",
        "entity_type": "other",
        "entity_document": "",
        "entity_bank": "",
    }

# ─── Generic Category Fallback ───────────────────────────────────────────────
_GENERIC_CATEGORY_KWS = {
    "Alimentação": ["restaurante", "lanchonete", "mercado", "supermercado", "ifood", "pizza", "burger", "padaria"],
    "Transporte":  ["uber", "99", "posto", "gasolina", "estacionamento"],
    "Moradia":     ["aluguel", "condomínio", "enel", "energia", "água", "internet", "vivo", "claro"],
    "Saúde":       ["farmácia", "droga", "hospital", "clínica", "médico"],
    "Assinaturas": ["netflix", "spotify", "amazon", "apple", "youtube", "disney"],
    "Salário":     ["salário", "pagamento salarial", "folha"],
    "Consórcios":  ["consórcio", "consorcio"],
    "Saque":       ["saque"],
    "Investimento":["nuinvest", "xp investimentos", "renda fixa", "tesouro"],
}

def _guess_category_generic(desc):
    d = desc.lower()
    for cat, kws in _GENERIC_CATEGORY_KWS.items():
        if any(k in d for k in kws):
            return cat
    return "Outros"

# ─── Date / Amount helpers ────────────────────────────────────────────────────
_DATE_FORMATS = ["%d/%m/%Y", "%d/%m/%y", "%Y-%m-%d", "%m/%d/%Y"]

def _parse_date(s):
    from datetime import datetime
    s = s.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None

def _parse_amount(s):
    s = str(s).strip().replace("R$", "").replace(" ", "").strip()
    if "," in s and "." in s:
        s = s.replace(".", "").replace(",", ".")
    elif "," in s:
        s = s.replace(",", ".")
    try:
        return int(round(float(s) * 100))
    except (ValueError, TypeError):
        return None

def _strip_accents(s):
    import unicodedata
    return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn')

def _find_col(headers, candidates):
    lowered = {_strip_accents(h.lower().strip()): h for h in headers}
    for c in candidates:
        if not c: continue
        key = _strip_accents(c.lower().strip())
        if key in lowered:
            return lowered[key]
    # Fallback to similar matches if no exact match
    for h in headers:
        hl = _strip_accents(h.lower())
        for c in candidates:
            if c and _strip_accents(c.lower()) in hl:
                return h
    return headers[0] if headers else ""

def _get(row, col):
    if not col:
        return ""
    return row.get(col, "").strip()

# ─── Main Parser ──────────────────────────────────────────────────────────────

def parse_csv_statement(file_bytes, bank="generic"):
    """
    Parse a bank statement CSV and return a list of transaction dicts.
    Each dict: date, description, category, amount, type, external_uid,
                entity_name, entity_type, entity_document, entity_bank
    """
    profile = PROFILES.get(bank, PROFILES["generic"])
    print(f"Profile: {profile}")
    content = None
    for enc in dict.fromkeys([profile["encoding"], "utf-8", "latin-1"]):
        try:
            content = file_bytes.decode(enc)
            break
        except (UnicodeDecodeError, LookupError):
            continue
    if content is None:
        return []

    if content.startswith("\ufeff"):
        content = content[1:]

    # Skip leading junk lines (Inter CSVs often have metadata headers)
    content_lines = [l.strip() for l in content.splitlines()]
    
    # NEW: Manual skip_lines has precedence
    skip_lines = profile.get('skip_lines', 0)
    if skip_lines > 0:
        content_lines = content_lines[skip_lines:]
        header_idx = skip_lines
    else:
        header_idx = -1
        keywords = ["data", "descri\u00e7\u00e3o", "valor", "hist\u00f3rico", "lan\u00e7amento", "date", "amount"]
        for i, line in enumerate(content_lines):
            line_lower = _strip_accents(line.lower())
            if any(kw in line_lower for kw in keywords):
                header_idx = i
                break
        if header_idx == -1: header_idx = 0
        content_lines = content_lines[header_idx:]

    content = "\n".join(content_lines)

    # Robust delimiter detection
    delims = [profile.get("delimiter", ","), ";", ",", "\t", "|"]
    best_rows = []
    best_headers = []
    
    quotechar = profile.get("quotechar", '"')
    
    for d in dict.fromkeys(delims):
        reader = csv.DictReader(io.StringIO(content), delimiter=d, quotechar=quotechar)
        rows = list(reader)
        if not rows: continue
        headers = [h for h in list(rows[0].keys()) if h] # Filter empty headers
        # If we split into 2+ cols and it looks like a header (contains keywords or is profile suggest)
        if len(headers) >= 2:
            best_rows = rows
            best_headers = headers
            break
            
    if not best_rows:
        return {"transactions": [], "ignored": []}

    rows = best_rows
    headers = best_headers

    # Always use _find_col with profile suggestions for robustness
    date_col   = _find_col(headers, [profile.get("date_col"), "data", "date", "data do lan\u00e7amento", "data lan\u00e7amento"])
    amount_col = _find_col(headers, [profile.get("amount_col"), "valor", "amount"])
    final_balance_col = _find_col(headers, [profile.get("balance_col"), "saldo", "balance"])
    desc_col   = _find_col(headers, [profile.get("desc_col"), "descri\u00e7\u00e3o", "descricao", "historico", "hist\u00f3rico", "lan\u00e7amento"])
    uid_col    = _find_col(headers, [profile.get("uid_col"), "identificador", "id", "uid"]) if profile.get("uid_col") else ""
    cat_col    = _find_col(headers, [profile.get("cat_col"), "categoria", "category"]) if profile.get("cat_col") else ""

    print(f"Coluna uid: {uid_col}")
    id_cols = profile.get('id_cols', [])

    transactions = []
    ignored_parse = []
    for i, row in enumerate(rows):
        line_num = header_idx + i + 2  # +1 for 0-indexing skip, +1 for header
        date_raw   = _get(row, date_col)
        amount_raw = _get(row, amount_col)
        desc       = _get(row, desc_col) or ""
        uid        = _get(row, uid_col)
        raw_uid    = uid

        if id_cols:
            # Custom idempotency hashing
            id_vals = [f"{col}:{_get(row, col)}" for col in id_cols]
            uid = hashlib.md5("|".join(id_vals).encode('utf-8')).hexdigest()

        if profile.get('merge_uid_with_column'):
            uid = f"merge1|{uid}|{_get(row, profile.get('merge_uid_with_column'))}"
            if profile.get('merge_uid_with_column_2'):
                uid = f"merge2|{uid}|{_get(row, profile.get('merge_uid_with_column_2'))}"
            uid = hashlib.md5(uid.encode('utf-8')).hexdigest()

        if not uid:
            # Generate fallback stable hash
            final_balance = _get(row, final_balance_col) or ''
            raw_id = f"{date_raw}|{desc}|{amount_raw}|{final_balance}"
            uid = hashlib.md5(raw_id.encode('utf-8')).hexdigest()
            
        csv_cat    = _get(row, cat_col) or ""
        if not date_raw and not amount_raw:
            ignored_parse.append({"line": f"{line_num}", "reason": "vazio"})
            continue
            
        date   = _parse_date(date_raw)
        amount = _parse_amount(amount_raw)
        if not date or amount is None:
            if date_raw or amount_raw:
                ignored_parse.append({"line": line_num, "reason": "formato_invalido", "date": date_raw, "amount": amount_raw})
            continue

        trans_type = "expense" if amount < 0 else "income"

        # Parse bank-specific patterns for richer entity/category data
        if bank == "nubank":
            parsed = parse_nubank_description(desc)
        elif bank == "inter":
            parsed = parse_inter_description(desc, amount_sign=-1 if amount < 0 else 1)
        else:
            parsed = {
                "category": csv_cat or _guess_category_generic(desc),
                "entity_name": "",
                "entity_type": "other",
                "entity_document": "",
                "entity_bank": "",
            }

        transactions.append({
            "line": line_num,
            "date": date,
            "description": desc.strip(),
            "category": parsed["category"],
            "amount": abs(amount),
            "type": trans_type,
            "external_uid": uid,
            "raw_external_uid": raw_uid,
            "entity_name":     parsed["entity_name"],
            "entity_type":     parsed["entity_type"],
            "entity_document": parsed["entity_document"],
            "entity_bank":     parsed["entity_bank"],
        })

    return {"transactions": transactions, "ignored": ignored_parse}
