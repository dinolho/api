from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import database as db_module
from database import get_db_connection, init_db, migrate_db
import os, json, time, hmac, hashlib, base64, secrets, re, sqlite3
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt as pyjwt
import pyotp
import auth_db
from dotenv import load_dotenv
import re as _re

if os.environ.get('ENCRYPTION_KEY') is None:
    load_dotenv() 

print(f"ENVIRONMENT: {os.environ.get('ENVIRONMENT')}")

app = Flask(__name__, static_folder=None)
CORS(app)

# ─── Auth DB init ─────────────────────────────────────────────
auth_db.init_auth_db()

JWT_SECRET   = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY_H = int(os.environ.get('JWT_EXPIRY_H', 168))  # 7 days

print(f"JWT_EXPIRY_H: {JWT_EXPIRY_H}")

_PUBLIC_PATHS = {
    '/api/auth/login', '/api/auth/register', '/api/auth/verify-2fa',
    '/api/auth/logout', '/api/config', '/api/auth/status',
    '/api/auth/pin/verify', '/api/auth/pin/set'
}

def _make_token(user_id: str, org_id: str | None, kind: str = 'full') -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=(5/60 if kind == 'temp' else JWT_EXPIRY_H))
    return pyjwt.encode({'user_id': user_id, 'org_id': org_id, 'kind': kind, 'exp': exp},
                        JWT_SECRET, algorithm='HS256')

def _decode_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except pyjwt.PyJWTError:
        return None

def require_auth(f):
    """JWT guard decorator — sets request.current_user and request.current_org_id."""
    @wraps(f)
    def decorated(*args, **kwargs):
        hdr = request.headers.get('Authorization', '')
        if not hdr.startswith('Bearer '):
            return jsonify({'error': 'Autenticação necessária'}), 401
        payload = _decode_token(hdr[7:])
        if not payload or payload.get('kind') != 'full':
            return jsonify({'error': 'Token inválido ou expirado'}), 401
        user = auth_db.get_user_by_id(payload['user_id'])
        if not user:
            return jsonify({'error': 'Usuário não encontrado'}), 401
        request.current_user    = user
        request.current_org_id  = payload.get('org_id')
        return f(*args, **kwargs)
    return decorated

def require_org_role(*roles):
    """Requires current user to have one of the given roles in the current org."""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated(*args, **kwargs):
            org_id = kwargs.get('org_id') or request.current_org_id
            role   = auth_db.get_member_role(org_id, request.current_user['id'])
            if role not in roles:
                return jsonify({'error': 'Permissão insuficiente'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Before-request guard ─────────────────────────────────────
@app.before_request
def check_auth_guard():
    """Protect all /api/* routes except public paths."""
    path = request.path
    if not path.startswith('/api/'):
        return
    if path in _PUBLIC_PATHS:
        return
    if request.method == 'OPTIONS':
        return
    hdr = request.headers.get('Authorization', '')
    if not hdr.startswith('Bearer '):
        return jsonify({'error': 'Autenticação necessária', 'code': 'UNAUTHENTICATED'}), 401
    payload = _decode_token(hdr[7:])
    if not payload or payload.get('kind') != 'full':
        return jsonify({'error': 'Token inválido ou expirado', 'code': 'INVALID_TOKEN'}), 401
    user = auth_db.get_user_by_id(payload['user_id'])
    if not user:
        return jsonify({'error': 'Usuário não encontrado', 'code': 'USER_NOT_FOUND'}), 401
    request.current_user   = user
    request.current_org_id = payload.get('org_id')

# ─── AUTH ENDPOINTS ───────────────────────────────────────────

def _safe_user(u: dict) -> dict:
    return {k: v for k, v in u.items() if k not in ('password_hash', 'totp_secret')}

@app.route('/api/auth/register', methods=['POST'])
def auth_register():
    d = request.json or {}
    email    = (d.get('email')    or '').strip().lower()
    password = (d.get('password') or '').strip()
    name     = (d.get('name')     or '').strip()
    if not email or not password:
        return jsonify({'error': 'E-mail e senha são obrigatórios'}), 400
    if len(password) < 8:
        return jsonify({'error': 'A senha deve ter pelo menos 8 caracteres'}), 400
    if auth_db.get_user_by_email(email):
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    user = auth_db.create_user(email, password, name or email.split('@')[0])
    token = _make_token(user['id'], None)
    return jsonify({'token': token, 'user': _safe_user(user)}), 201

@app.route('/api/auth/login', methods=['POST'])
def auth_login():
    d = request.json or {}
    email    = (d.get('email')    or '').strip().lower()
    password = (d.get('password') or '').strip()
    user = auth_db.get_user_by_email(email)
    if not user or not auth_db.verify_password(user, password):
        return jsonify({'error': 'E-mail ou senha inválidos'}), 401
    # 2FA required?
    if user['totp_enabled']:
        temp = _make_token(user['id'], None, kind='temp')
        return jsonify({'requires_2fa': True, 'temp_token': temp})
    # Check if active org requires 2FA
    org_id = d.get('org_id') or None
    if org_id:
        org  = auth_db.get_org(org_id)
        role = auth_db.get_member_role(org_id, user['id'])
        if org and org['require_2fa'] and not user['totp_enabled']:
            return jsonify({'error': 'Esta organização exige autenticação de dois fatores (2FA). Ative o 2FA antes de continuar.'}), 403
    token = _make_token(user['id'], org_id)
    return jsonify({'token': token, 'user': _safe_user(user)})

@app.route('/api/auth/verify-2fa', methods=['POST'])
def auth_verify_2fa():
    d = request.json or {}
    temp_token = (d.get('temp_token') or '').strip()
    code       = (d.get('code')       or '').strip()
    org_id     = d.get('org_id') or None
    payload = _decode_token(temp_token)
    if not payload or payload.get('kind') != 'temp':
        return jsonify({'error': 'Token temporário inválido'}), 401
    user = auth_db.get_user_by_id(payload['user_id'])
    if not user or not user['totp_secret']:
        return jsonify({'error': 'Usuário sem 2FA configurado'}), 400
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Código 2FA inválido'}), 401
    token = _make_token(user['id'], org_id)
    return jsonify({'token': token, 'user': _safe_user(user)})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def auth_me():
    user  = request.current_user
    orgs  = auth_db.get_user_orgs(user['id'])
    org   = auth_db.get_org(request.current_org_id) if request.current_org_id else None
    return jsonify({'user': _safe_user(user), 'orgs': orgs, 'active_org': org})

@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    return jsonify({'status': 'ok'})

@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def auth_change_password():
    d = request.json or {}
    current  = d.get('current_password', '')
    new_pw   = d.get('new_password', '')
    user = request.current_user
    if not auth_db.verify_password(user, current):
        return jsonify({'error': 'Senha atual incorreta'}), 401
    if len(new_pw) < 8:
        return jsonify({'error': 'A nova senha deve ter pelo menos 8 caracteres'}), 400
    auth_db.update_user_password(user['id'], new_pw)
    return jsonify({'status': 'ok'})

# ── 2FA setup ─────────────────────────────────────────────────
@app.route('/api/auth/2fa/setup', methods=['POST'])
@require_auth
def auth_2fa_setup():
    user   = request.current_user
    secret = pyotp.random_base32()
    # Save secret but don't enable yet
    auth_db.update_user_totp(user['id'], secret, enabled=False)
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=user['email'], issuer_name='FinancePro')
    qr_url = f"https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl={uri}"
    return jsonify({'secret': secret, 'uri': uri, 'qr_url': qr_url})

@app.route('/api/auth/2fa/enable', methods=['POST'])
@require_auth
def auth_2fa_enable():
    d    = request.json or {}
    code = (d.get('code') or '').strip()
    user = auth_db.get_user_by_id(request.current_user['id'])
    if not user or not user['totp_secret']:
        return jsonify({'error': 'Execute /2fa/setup primeiro'}), 400
    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Código inválido. Verifique a hora do seu dispositivo.'}), 400
    auth_db.update_user_totp(user['id'], user['totp_secret'], enabled=True)
    return jsonify({'status': 'ok', 'message': '2FA ativado com sucesso!'})

@app.route('/api/auth/2fa/disable', methods=['POST'])
@require_auth
def auth_2fa_disable():
    d    = request.json or {}
    code = (d.get('code') or '').strip()
    user = auth_db.get_user_by_id(request.current_user['id'])
    # Check if org requires 2FA
    if request.current_org_id:
        org = auth_db.get_org(request.current_org_id)
        if org and org['require_2fa']:
            return jsonify({'error': 'Sua organização exige 2FA ativo. Não é possível desativar.'}), 403
    if user['totp_enabled']:
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(code, valid_window=1):
            return jsonify({'error': 'Código inválido'}), 400
    auth_db.update_user_totp(user['id'], None, enabled=False)
    return jsonify({'status': 'ok'})

# ─── ORGANIZATION ENDPOINTS ───────────────────────────────────

@app.route('/api/user/orgs', methods=['GET'])
@require_auth
def user_list_orgs():
    orgs = auth_db.get_user_orgs(request.current_user['id'])
    return jsonify(orgs)

@app.route('/api/user/orgs', methods=['POST'])
@require_auth
def user_create_org():
    d    = request.json or {}
    name = (d.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nome da organização é obrigatório'}), 400
    require_2fa = d.get('require_2fa', True)
    # Cannot require 2FA if the owner doesn't have it enabled yet
    if require_2fa and not request.current_user.get('totp_enabled'):
        return jsonify({
            'error': 'Você precisa ativar o 2FA na sua conta antes de criar uma organização que exige 2FA dos membros.',
            'code': 'OWNER_NEEDS_2FA'
        }), 400
    org = auth_db.create_org(name, request.current_user['id'], require_2fa)
    return jsonify(org), 201

@app.route('/api/orgs/<org_id>', methods=['GET'])
@require_auth
def get_org_detail(org_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if not role:
        return jsonify({'error': 'Acesso negado'}), 403
    org = auth_db.get_org(org_id)
    return jsonify({**org, 'your_role': role} if org else {'error': 'Não encontrada'})

@app.route('/api/orgs/<org_id>', methods=['PUT'])
@require_auth
def update_org_detail(org_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    d = request.json or {}
    auth_db.update_org(org_id, name=d.get('name'), require_2fa=d.get('require_2fa'))
    return jsonify({'status': 'ok'})

@app.route('/api/orgs/<org_id>/switch', methods=['POST'])
@require_auth
def switch_org(org_id):
    """Issue a new JWT bound to the given org."""
    user = request.current_user
    role = auth_db.get_member_role(org_id, user['id'])
    if not role:
        return jsonify({'error': 'Você não é membro desta organização'}), 403
    org = auth_db.get_org(org_id)
    if org and org['require_2fa'] and not user['totp_enabled']:
        return jsonify({'error': 'Esta organização exige 2FA. Ative o 2FA primeiro.', 'code': 'REQUIRES_2FA'}), 403
    token = _make_token(user['id'], org_id)
    return jsonify({'token': token, 'org': org})

@app.route('/api/orgs/<org_id>/members', methods=['GET'])
@require_auth
def org_get_members(org_id):
    if not auth_db.get_member_role(org_id, request.current_user['id']):
        return jsonify({'error': 'Acesso negado'}), 403
    return jsonify(auth_db.get_org_members(org_id))

@app.route('/api/orgs/<org_id>/members/invite', methods=['POST'])
@require_auth
def org_invite_member(org_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Apenas owners e admins podem convidar membros'}), 403
    d = request.json or {}
    email = (d.get('email') or '').strip().lower()
    new_role = d.get('role', 'member')
    if new_role not in ('member', 'admin'):
        return jsonify({'error': 'Papel inválido'}), 400
    user = auth_db.get_user_by_email(email)
    if not user:
        return jsonify({'error': f'Usuário com e-mail "{email}" não encontrado. Peça que ele se cadastre primeiro.'}), 404
    added = auth_db.add_member(org_id, user['id'], new_role, request.current_user['id'])
    if not added:
        return jsonify({'error': 'Usuário já é membro desta organização'}), 409
    return jsonify({'status': 'ok', 'user': _safe_user(user)}), 201

@app.route('/api/orgs/<org_id>/members/<user_id>/role', methods=['PUT'])
@require_auth
def org_set_member_role(org_id, user_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role != 'owner':
        return jsonify({'error': 'Apenas o proprietário pode alterar papéis'}), 403
    if user_id == request.current_user['id']:
        return jsonify({'error': 'Não é possível alterar seu próprio papel'}), 400
    d = request.json or {}
    new_role = d.get('role', 'member')
    if new_role not in ('member', 'admin'):
        return jsonify({'error': 'Papel inválido'}), 400
    auth_db.set_member_role(org_id, user_id, new_role)
    return jsonify({'status': 'ok'})

@app.route('/api/orgs/<org_id>/members/<user_id>', methods=['DELETE'])
@require_auth
def org_remove_member(org_id, user_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    is_self = user_id == request.current_user['id']
    if not is_self and role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    target_role = auth_db.get_member_role(org_id, user_id)
    if target_role == 'owner' and not is_self:
        return jsonify({'error': 'Não é possível remover o proprietário'}), 400
    auth_db.remove_member(org_id, user_id)
    return jsonify({'status': 'ok'})

# ── Org Databases ─────────────────────────────────────────────
@app.route('/api/orgs/<org_id>/databases', methods=['GET'])
@require_auth
def org_list_databases(org_id):
    if not auth_db.get_member_role(org_id, request.current_user['id']):
        return jsonify({'error': 'Acesso negado'}), 403
    dbs = auth_db.get_org_databases(org_id)
    return jsonify(dbs)

@app.route('/api/orgs/<org_id>/databases', methods=['POST'])
@require_auth
def org_add_database(org_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    d = request.json or {}
    db_path = (d.get('db_path') or '').strip()
    # Resolve relative paths against DB_DIRECTORY
    if db_path and not os.path.isabs(db_path):
        db_path = os.path.join(db_module.DB_DIRECTORY, db_path)
    
    db_name = (d.get('db_name') or d.get('name') or '').strip()
    if not db_path:
        return jsonify({'error': 'db_path é obrigatório'}), 400
    entry = auth_db.add_org_database(org_id, db_path, db_name, request.current_user['id'],
                                     d.get('access_mode', 'all_members'))
    return jsonify(entry), 201

@app.route('/api/orgs/<org_id>/databases/<db_id>', methods=['DELETE'])
@require_auth
def org_remove_database(org_id, db_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    auth_db.remove_org_database(db_id)
    return jsonify({'status': 'ok'})

@app.route('/api/orgs/<org_id>/databases/<db_id>/access', methods=['GET'])
@require_auth
def org_list_db_access(org_id, db_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    return jsonify(auth_db.get_db_access_list(db_id))

@app.route('/api/orgs/<org_id>/databases/<db_id>/access/<user_id>', methods=['PUT'])
@require_auth
def org_grant_db_access(org_id, db_id, user_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    auth_db.grant_db_access(db_id, user_id, request.current_user['id'])
    return jsonify({'status': 'ok'})

@app.route('/api/orgs/<org_id>/databases/<db_id>/access/<user_id>', methods=['DELETE'])
@require_auth
def org_revoke_db_access(org_id, db_id, user_id):
    role = auth_db.get_member_role(org_id, request.current_user['id'])
    if role not in ('owner', 'admin'):
        return jsonify({'error': 'Permissão insuficiente'}), 403
    auth_db.revoke_db_access(db_id, user_id)
    return jsonify({'status': 'ok'})


# ─── Cross-Origin Isolation (required for SharedArrayBuffer / SQLite Wasm) ───
@app.after_request
def add_coi_headers(response):
    response.headers['Cross-Origin-Opener-Policy']   = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    return response

# ─── AUTH & SECURITY ────────────────────────────────────────────────────────
APP_SECRET = os.environ.get('APP_SECRET', secrets.token_hex(32))

# ─── FILES DIRECTORY ─────────────────────────────────────────────────────────
FILES_DIRECTORY = os.environ.get(
    'FILES_DIRECTORY',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files')
)
os.makedirs(FILES_DIRECTORY, exist_ok=True)

# Key used by the frontend encryptFile() — raw UTF-8 bytes, 16/32 chars expected
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '')


def _decrypt_enc_bytes(raw: bytes) -> bytes:
    """
    Decrypt bytes produced by sync_r2.py:   IV(12 bytes, raw) || ciphertext+GCMtag

    The IV originates from R2 custom metadata (written by the Cloudflare Worker).
    sync_r2.py fetches the IV and prepends it to the raw ciphertext before saving.

    Fallback: base64-encoded layout (legacy / direct browser exports).
    The key is the UTF-8 encoding of ENCRYPTION_KEY (must be 16, 24 or 32 bytes).
    Raises ValueError with a human-readable message on any failure.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    key_bytes = ENCRYPTION_KEY.encode('utf-8')
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError(
            f'ENCRYPTION_KEY tem {len(key_bytes)} bytes — deve ter 16, 24 ou 32 caracteres.'
        )

    aesgcm = AESGCM(key_bytes)

    def _try_decrypt(data: bytes) -> bytes | None:
        if len(data) < 12 + 16:
            return None
        try:
            return aesgcm.decrypt(data[:12], data[12:], None)   # IV-first (primary)
        except InvalidTag:
            pass
        try:
            return aesgcm.decrypt(data[-12:], data[:-12], None)  # IV-last (fallback)
        except InvalidTag:
            pass
        return None

    # 1. Primary: raw binary IV-first (format produced by sync_r2.py)
    result = _try_decrypt(raw)
    if result is not None:
        return result

    # 2. Fallback: base64-encoded (direct browser export or legacy files)
    try:
        result = _try_decrypt(base64.b64decode(raw.strip()))
        if result is not None:
            return result
    except Exception:
        pass

    raise ValueError(
        'Falha na descriptografia: verifique se ENCRYPTION_KEY está correta '
        'e se o arquivo foi sincronizado via sync_r2.py.'
    )




def generate_auth_token():
    payload = {'iat': int(time.time()), 'exp': int(time.time()) + 86400} # 24h
    payload_str = json.dumps(payload)
    signature = hmac.new(APP_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload_str}.{signature}".encode()).decode()

def verify_auth_token(token):
    if not token: return None
    try:
        decoded = base64.b64decode(token).decode()
        payload_str, signature = decoded.rsplit('.', 1)
        expected_sig = hmac.new(APP_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig): return None
        payload = json.loads(payload_str)
        if payload['exp'] < time.time(): return None
        
        # Check invalidation
        last_inv = auth_db.get_central_config('last_token_invalidation_at')
        pin      = auth_db.get_central_config('privacy_pin_hash')
        
        # If no PIN is configured, skip verification
        if not pin: return payload
        
        if last_inv and int(last_inv) > payload['iat']: return None
        return payload
    except: return None

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # PIN token lives in X-Pin-Token, NOT Authorization (which is for user JWT)
        token = request.headers.get('X-Pin-Token', '')
        # Only enforce if a PIN is set
        pin = auth_db.get_central_config('privacy_pin_hash')
        if pin:
            if not verify_auth_token(token):
                return jsonify({'status': 'unauthorized', 'message': 'PIN required', 'code': 'PIN_REQUIRED'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/pin/verify', methods=['POST'])
def verify_pin():
    d = request.json
    pin = d.get('pin')
    stored = auth_db.get_central_config('privacy_pin_hash')
    if not stored:
        return jsonify({'status': 'success', 'token': generate_auth_token()})
    if check_password_hash(stored, pin):
        return jsonify({'status': 'success', 'token': generate_auth_token()})
    return jsonify({'status': 'error', 'message': 'PIN incorreto'}), 401

@app.route('/api/auth/pin/set', methods=['POST'])
def set_pin():
    d = request.json
    old_pin = d.get('old_pin')
    new_pin = d.get('new_pin')
    stored = auth_db.get_central_config('privacy_pin_hash')
    if stored:
        if not old_pin or not check_password_hash(stored, old_pin):
            return jsonify({'status': 'error', 'message': 'PIN atual incorreto'}), 400
    
    hashed = generate_password_hash(new_pin) if new_pin else None
    auth_db.set_central_config('privacy_pin_hash', hashed)
    return jsonify({'status': 'success'})

@app.route('/api/auth/invalidate', methods=['POST'])
def invalidate_tokens():
    # Called when privacy mode is activated
    auth_db.set_central_config('last_token_invalidation_at', str(int(time.time())))
    return jsonify({'status': 'success'})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    pin = auth_db.get_central_config('privacy_pin_hash')
    return jsonify({'has_pin': bool(pin)})

@app.before_request
def check_auth_global():
    if not request.path.startswith('/api/'):
        return
    # White-list
    public = [
        '/api/auth/pin/verify',
        '/api/auth/status',
        '/api/auth/invalidate',
        '/api/config',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/verify-2fa',
        '/api/auth/logout',
        '/api/auth/me' # Allow /me to check if logged in even if PIN is pending
    ]
    if request.path in public:
        return
    
    # Check if a PIN is actually configured
    pin = auth_db.get_central_config('privacy_pin_hash')
    if not pin:
        return
    
    # PIN token lives in a separate header to avoid colliding with the user JWT
    token = request.headers.get('X-Pin-Token', '')
    if not verify_auth_token(token):
        return jsonify({'status': 'unauthorized', 'message': 'PIN required to access locked data', 'code': 'PIN_REQUIRED'}), 401

@app.route('/')
def index():
    return jsonify({'status': 'Finance API running'})

# ─── DATABASE MANAGEMENT ─────────────────────────────────────────────────────

def _db_summary(id: str, db_path: str) -> dict:
    """Open any .db file temporarily and return a summary dict."""
    import sqlite3 as _sq
    
    # Resolve relative paths against DB_DIRECTORY
    if not os.path.isabs(db_path):
        db_path = os.path.join(db_module.DB_DIRECTORY, db_path)
    
    result = {
        "id": id,
        'path': db_path,
        'name': os.path.basename(db_path),
        'size': os.path.getsize(db_path) if os.path.exists(db_path) else 0,
        'is_current': os.path.abspath(db_path) == os.path.abspath(db_module.get_current_db_path()),
    }
    try:
        conn = _sq.connect(db_path, timeout=2.0)
        conn.row_factory = _sq.Row
        result['total_balance'] = conn.execute('SELECT COALESCE(SUM(balance),0) FROM accounts').fetchone()[0]
        result['account_count'] = conn.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]
        result['txn_count']     = conn.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]
        result['last_txn_date'] = conn.execute('SELECT MAX(date) FROM transactions').fetchone()[0]
        # version
        ver_row = conn.execute("SELECT value FROM system_config WHERE key='db_version'").fetchone()
        result['db_version'] = ver_row[0] if ver_row else '—'
        # PIN protection flag (so frontend can hide values for locked DBs)
        pin_row = conn.execute("SELECT value FROM system_config WHERE key='privacy_pin_hash'").fetchone()
        result['has_pin'] = bool(pin_row and pin_row[0])
        # income/expense totals for current month
        ym = datetime.now().strftime('%Y-%m')
        result['month_income']  = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='income' AND date LIKE ?", (ym+'%',)
        ).fetchone()[0]
        result['month_expense'] = conn.execute(
            "SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='expense' AND date LIKE ?", (ym+'%',)
        ).fetchone()[0]
        conn.close()
    except Exception as e:
        result['error'] = str(e)
    return result


@app.route('/api/databases', methods=['GET'])
@require_auth
def list_databases():
    """Return summary info only for databases linked to the current organization."""
    org_id = request.current_org_id
    if not org_id:
        return jsonify([])
    
    # Get databases registered for this organization
    org_dbs = auth_db.get_org_databases(org_id)
    
    # Merge with file summary info
    results = []
    for odb in org_dbs:
        summary = _db_summary(odb['id'], odb['db_path'])
        # Use the name registered in org_databases if it exists
        if odb.get('db_name'):
            summary['name'] = odb['db_name']
        results.append(summary)
        
    return jsonify(results)


@app.route('/api/databases', methods=['POST'])
@require_auth
def create_database():
    """Create a new SQLite .db file, initialise its schema, link to org and select it."""
    org_id = request.current_org_id
    if not org_id:
        return jsonify({'error': 'Organização necessária para criar banco'}), 403

    data = request.json or {}
    raw_name = (data.get('name') or '').strip()
    if not raw_name:
        return jsonify({'error': 'name is required'}), 400
    # Sanitise: keep only safe chars
    import re
    safe_name = re.sub(r'[^\w\-]', '_', raw_name)
    if not safe_name.endswith('.db'):
        safe_name += '.db'
    db_path = os.path.join(db_module.DB_DIRECTORY, safe_name)
    if os.path.exists(db_path):
        return jsonify({'error': 'A database with this name already exists'}), 409
    # Bootstrap schema
    db_module.set_current_db(db_path)
    try:
        init_db()
        migrate_db()
        # Link to organization
        auth_db.add_org_database(org_id, db_path, raw_name, request.current_user['id'])
    except Exception as e:
        db_module.set_current_db(db_module.DB_PATH)
        return jsonify({'error': str(e)}), 500
    return jsonify({'status': 'created', 'path': db_path, 'name': safe_name}), 201


@app.route('/api/databases/current', methods=['GET'])
def get_current_database():
    path = db_module.get_current_db_path()
    return jsonify({
        'path': path,
        'name': os.path.basename(path),
        'is_current': True,
    })


@app.route('/api/databases/select', methods=['POST'])
def select_database():
    """Switch the active database for all subsequent requests."""
    data = request.json or {}
    path = (data.get('path') or '').strip()
    if not path:
        return jsonify({'error': 'path is required'}), 400
        
    # Resolve relative paths against DB_DIRECTORY
    if not os.path.isabs(path):
        path = os.path.join(db_module.DB_DIRECTORY, path)
        
    # Security: must be inside DB_DIRECTORY
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(os.path.abspath(db_module.DB_DIRECTORY)):
        return jsonify({'error': 'Invalid path'}), 403
    if not os.path.exists(abs_path):
        return jsonify({'error': 'File not found'}), 404
    db_module.set_current_db(abs_path)
    # Ensure schema is up-to-date on this DB
    try:
        migrate_db()
    except Exception:
        pass
    return jsonify({'status': 'ok', 'name': os.path.basename(abs_path), 'path': abs_path})


# ─── DB CONFIGS (user-registered connection configs, cloud-saved) ──────────────

def _ensure_db_configs_table(conn):
    conn.execute('''
        CREATE TABLE IF NOT EXISTS db_configs (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            type        TEXT NOT NULL DEFAULT 'api',
            base_url    TEXT,
            db_path     TEXT,
            filename    TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        )
    ''')


@app.route('/api/db-configs', methods=['GET'])
@require_auth
def get_db_configs():
    org_id  = request.current_org_id
    user_id = request.current_user['id']
    configs = auth_db.get_db_configs(org_id=org_id, user_id=user_id)
    
    results = []
    for d in configs:
        d['storageType'] = 'cloud'
        if d.get('db_path'):
            summary = _db_summary(d['id'],d['db_path'])
            d.update(summary)
            d['path'] = d.get('db_path')
        results.append(d)
    return jsonify(results)


@app.route('/api/db-configs', methods=['POST'])
@require_auth
def create_db_config():
    data    = request.json or {}
    org_id  = request.current_org_id
    user_id = request.current_user['id']
    
    db_path = data.get('db_path', '').strip()
    if db_path and not os.path.isabs(db_path):
        db_path = os.path.join(db_module.DB_DIRECTORY, db_path)

    entry = auth_db.add_org_database(
        org_id, 
        db_path, 
        data.get('name', 'Sem nome'), 
        user_id,
        type=data.get('type', 'api'),
        base_url=data.get('base_url', ''), 
        filename=data.get('filename', ''),
        user_id=user_id
    )
    return jsonify({'id': entry['id'], 'status': 'created'}), 201


@app.route('/api/db-configs/<cfg_id>', methods=['PUT'])
@require_auth
def update_db_config(cfg_id):
    data = request.json or {}
    auth_db.update_db_config(
        cfg_id, data.get('name'), data.get('type', 'api'),
        data.get('base_url', ''), data.get('db_path', ''), data.get('filename', '')
    )
    return jsonify({'status': 'ok'})


@app.route('/api/db-configs/<cfg_id>', methods=['DELETE'])
@require_auth
def delete_db_config(cfg_id):
    auth_db.remove_db_config(cfg_id)
    return jsonify({'status': 'ok'})


# ─── AI ASSISTANT ─────────────────────────────────────────────────────────────

_AI_CONFIG_KEYS = ['ai_enabled', 'ai_provider', 'ai_model', 'ai_api_key',
                   'ai_base_url', 'ai_system_prompt', 'ai_temperature']

def _get_ai_config(conn):
    cfg = {}
    for key in _AI_CONFIG_KEYS:
        row = conn.execute("SELECT value FROM system_config WHERE key=?", (key,)).fetchone()
        cfg[key] = row['value'] if row else None
    return cfg


@app.route('/api/ai/config', methods=['GET'])
def get_ai_config():
    conn = get_db_connection()
    cfg = _get_ai_config(conn)
    conn.close()
    # Mask API key in response
    masked = {**cfg}
    if masked.get('ai_api_key'):
        k = masked['ai_api_key']
        masked['ai_api_key'] = k[:6] + '••••••••' + k[-4:] if len(k) > 10 else '••••••••'
        masked['ai_api_key_set'] = True
    else:
        masked['ai_api_key_set'] = False
    return jsonify(masked)


@app.route('/api/ai/config', methods=['POST'])
def save_ai_config():
    data = request.json or {}
    conn = get_db_connection()
    for key, value in data.items():
        if key in _AI_CONFIG_KEYS and value is not None:
            # Don't overwrite the key if the user sent back the masked value
            if key == 'ai_api_key' and '••••' in str(value):
                continue
            conn.execute(
                "INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, datetime('now'))",
                (key, str(value))
            )
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


def _get_db_schema(conn):
    """Return a compact schema description for the AI system prompt."""
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    schema_lines = []
    for (tname,) in tables:
        if tname.startswith('sqlite_') or tname in ('spatial_ref_sys',):
            continue
        cols = conn.execute(f"PRAGMA table_info({tname})").fetchall()
        col_defs = ', '.join(f"{c['name']} {c['type']}" for c in cols)
        schema_lines.append(f"  {tname}({col_defs})")
    return '\n'.join(schema_lines)


def _ai_tools():
    return [
        {
            "type": "function",
            "function": {
                "name": "query_database",
                "description": (
                    "Execute a read-only SQLite SELECT query on the user's financial database. "
                    "Use this to look up transactions, balances, categories, entities, tags, etc. "
                    "Values marked as 'INTEGER' for amounts are stored in CENTAVOS — divide by 100 for reais."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "A valid SQLite SELECT query. ONLY SELECT is allowed."
                        },
                        "reason": {
                            "type": "string",
                            "description": "One-line explanation of what this query returns"
                        }
                    },
                    "required": ["sql", "reason"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_financial_summary",
                "description": "Get a high-level summary: total balance across all accounts, current-month income & expense, top categories, and account list.",
                "parameters": {"type": "object", "properties": {}}
            }
        }
    ]


def _execute_tool(tool_name, args, conn):
    if tool_name == "query_database":
        sql = (args.get("sql") or "").strip()
        # Safety: only SELECT
        if not re.match(r'^\s*(?:SELECT|WITH\s)', sql, re.IGNORECASE):
            return {"error": "Apenas consultas SELECT são permitidas por segurança."}
        # Block dangerous keywords
        for kw in ('DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER', 'CREATE', 'ATTACH', 'DETACH'):
            if re.search(rf'\b{kw}\b', sql, re.IGNORECASE):
                return {"error": f"Operação {kw} não é permitida em modo somente leitura."}
        try:
            cur = conn.execute(sql)
            rows = [dict(r) for r in cur.fetchmany(200)]
            return {"rows": rows, "count": len(rows), "note": "truncated at 200 rows" if len(rows) == 200 else None}
        except Exception as exc:
            return {"error": str(exc)}

    elif tool_name == "get_financial_summary":
        try:
            ym = datetime.now().strftime('%Y-%m')
            balance  = conn.execute("SELECT COALESCE(SUM(balance),0) FROM accounts").fetchone()[0]
            accounts = [dict(r) for r in conn.execute("SELECT id,name,type,balance,currency,institution FROM accounts ORDER BY balance DESC").fetchall()]
            income   = conn.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='income'  AND date LIKE ?", (ym+'%',)).fetchone()[0]
            expense  = conn.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='expense' AND date LIKE ?", (ym+'%',)).fetchone()[0]
            total_tx = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            top_cats = [dict(r) for r in conn.execute(
                "SELECT category, SUM(amount) AS total FROM transactions WHERE type='expense' GROUP BY category ORDER BY total DESC LIMIT 5"
            ).fetchall()]
            return {
                "current_month": ym,
                "total_balance_centavos": balance,
                "total_balance_reais": round(balance / 100, 2),
                "month_income_reais":  round(income  / 100, 2),
                "month_expense_reais": round(expense / 100, 2),
                "month_net_reais":     round((income - expense) / 100, 2),
                "total_transactions": total_tx,
                "accounts": [{**a, 'balance_reais': round(a['balance']/100, 2)} for a in accounts],
                "top_expense_categories": top_cats,
            }
        except Exception as exc:
            return {"error": str(exc)}

    return {"error": f"Ferramenta desconhecida: {tool_name}"}


@app.route('/api/ai/chat', methods=['POST'])
def ai_chat():
    """Stream AI chat responses via Server-Sent Events with agentic tool-call loop."""
    data     = request.json or {}
    messages = data.get('messages', [])

    conn = get_db_connection()
    cfg  = _get_ai_config(conn)

    if cfg.get('ai_enabled') != '1':
        conn.close()
        return jsonify({'error': 'O assistente de IA não está ativado para este banco de dados.'}), 403

    api_key = (cfg.get('ai_api_key') or '').strip()
    if not api_key:
        conn.close()
        return jsonify({'error': 'Chave de API da IA não configurada. Vá em Configurações → IA para configurar.'}), 400

    model       = (cfg.get('ai_model') or 'gpt-4o-mini').strip()
    base_url    = (cfg.get('ai_base_url') or '').strip() or None
    temperature = float(cfg.get('ai_temperature') or 0.3)
    custom_sys  = (cfg.get('ai_system_prompt') or '').strip()

    # Build rich system prompt with live schema
    schema = _get_db_schema(conn)
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

    system_prompt = custom_sys or f"""Você é um assistente financeiro pessoal inteligente e preciso.
Você tem acesso direto ao banco de dados SQLite do usuário e pode consultar qualquer dado financeiro.

Data/hora atual: {now_str}

ESQUEMA DO BANCO DE DADOS:
{schema}

REGRAS IMPORTANTES:
- Valores de amount, balance e raw_amount estão em CENTAVOS (INTEGER). Sempre divida por 100 para exibir em reais.
- Responda sempre em português brasileiro claro e objetivo.
- Antes de responder sobre dados financeiros, SEMPRE use as ferramentas para buscar os dados atuais do banco.
- Apresente valores monetários no formato "R$ 1.234,56".
- Se o usuário pedir análises, calcule os dados e forneça insights úteis.
- Jamais invente dados — use apenas o que as ferramentas retornarem.
- Tipo income = receita, expense = despesa, transfer = transferência.
"""

    full_messages = [{"role": "system", "content": system_prompt}] + messages

    def generate():
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key, base_url=base_url)
            tools  = _ai_tools()
            cur_messages = [m.copy() if isinstance(m, dict) else m for m in full_messages]

            # Agentic loop
            for _iteration in range(8):  # max 8 tool-call rounds
                response = client.chat.completions.create(
                    model=model,
                    messages=cur_messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=temperature,
                )
                choice = response.choices[0]
                msg    = choice.message

                # Serialize the assistant message
                msg_dict = {"role": "assistant", "content": msg.content or ""}
                if msg.tool_calls:
                    msg_dict["tool_calls"] = [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in msg.tool_calls
                    ]
                cur_messages.append(msg_dict)

                if choice.finish_reason == "tool_calls" and msg.tool_calls:
                    for tc in msg.tool_calls:
                        try:
                            args = json.loads(tc.function.arguments)
                        except Exception:
                            args = {}

                        # Notify frontend: tool is being called
                        yield f"data: {json.dumps({'type':'tool_call','id':tc.id,'name':tc.function.name,'args':args})}\n\n"

                        result = _execute_tool(tc.function.name, args, conn)

                        yield f"data: {json.dumps({'type':'tool_result','id':tc.id,'result':result})}\n\n"

                        cur_messages.append({
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(result, ensure_ascii=False)
                        })
                else:
                    # Final text response
                    content = msg.content or ""
                    yield f"data: {json.dumps({'type':'content','text':content})}\n\n"
                    yield f"data: {json.dumps({'type':'done'})}\n\n"
                    break

        except Exception as exc:
            yield f"data: {json.dumps({'type':'error','message':str(exc)})}\n\n"
        finally:
            conn.close()

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def _get_redaction_context(conn):
    """Returns (rules_list, is_enabled_bool)."""
    rules = [r['text'] for r in conn.execute('SELECT text FROM redacted_texts').fetchall()]
    cfg = conn.execute('SELECT value FROM system_config WHERE key=?', ('redaction_enabled',)).fetchone()
    enabled = (cfg['value'] == '1') if cfg else False
    return rules, enabled

def _redact(text, rules, enabled):
    if not enabled or not text:
        return text
    for rule in rules:
        if not rule: continue
        text = text.replace(rule, '[redacted]')
    return text

def _sync_tags(conn, kind, owner_id, tag_names):
    """Upsert tags and sync the junction table for a transaction or entity."""
    junction = 'transaction_tags' if kind == 'transaction' else 'entity_tags'
    fk_col   = 'transaction_id' if kind == 'transaction' else 'entity_id'
    # Remove all existing associations
    conn.execute(f'DELETE FROM {junction} WHERE {fk_col}=?', (owner_id,))
    for name in (tag_names or []):
        name = name.strip().lower()
        if not name:
            continue
        # Upsert tag
        conn.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (name,))
        tag_id = conn.execute('SELECT id FROM tags WHERE name=?', (name,)).fetchone()['id']
        conn.execute(f'INSERT OR IGNORE INTO {junction} ({fk_col}, tag_id) VALUES (?,?)', (owner_id, tag_id))

# ─── CATEGORIES ──────────────────────────────────────────────────────────────

@app.route('/api/categories', methods=['GET'])
def get_categories():
    conn = get_db_connection()
    # Safe migration — add color/icon if they don't exist
    for col, default in [('color',"'#6366f1'"), ('icon',"'tag'")]:
        try:
            conn.execute(f"ALTER TABLE categories ADD COLUMN {col} TEXT DEFAULT {default}")
            conn.commit()
        except Exception:
            pass
    rows = conn.execute('''
        SELECT c.*, 
               COUNT(t.id) as usage_count,
               SUM(CASE WHEN t.type='expense' THEN t.amount ELSE 0 END) as total_spent,
               SUM(CASE WHEN t.type='income' THEN t.amount ELSE 0 END) as total_received
        FROM categories c
        LEFT JOIN transactions t ON t.category = c.name
        LEFT JOIN entities e     ON t.entity_id = e.id
        WHERE (e.exclude_from_reports IS NULL OR e.exclude_from_reports = 0)
        GROUP BY c.id
        ORDER BY c.name
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/categories', methods=['POST'])
def create_category():
    d = request.json
    conn = get_db_connection()
    conn.execute('INSERT INTO categories (name, color, icon) VALUES (?,?,?)',
                 (d['name'], d.get('color','#6366f1'), d.get('icon','tag')))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'}), 201

@app.route('/api/categories/<int:id>', methods=['PUT'])
def update_category(id):
    d = request.json
    conn = get_db_connection()
    old = conn.execute('SELECT name FROM categories WHERE id=?', (id,)).fetchone()
    conn.execute('UPDATE categories SET name=?, color=?, icon=? WHERE id=?',
                 (d['name'], d.get('color','#6366f1'), d.get('icon','tag'), id))
    # Cascade rename to transactions
    if old and old['name'] != d['name']:
        conn.execute("UPDATE transactions SET category=? WHERE category=?", (d['name'], old['name']))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

@app.route('/api/categories/<int:id>', methods=['DELETE'])
def delete_category(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM categories WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

# ─── TAGS ────────────────────────────────────────────────────────────────────

@app.route('/api/tags', methods=['GET'])
def get_tags():
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT t.id, t.name,
               COUNT(DISTINCT tt.transaction_id) as txn_count,
               COUNT(DISTINCT et.entity_id)      as entity_count,
               SUM(CASE WHEN tx.type='expense' THEN tx.amount ELSE 0 END) as total_spent,
               SUM(CASE WHEN tx.type='income' THEN tx.amount ELSE 0 END) as total_received
        FROM tags t
        LEFT JOIN transaction_tags tt ON tt.tag_id = t.id
        LEFT JOIN entity_tags      et ON et.tag_id = t.id
        LEFT JOIN transactions     tx ON tx.id = tt.transaction_id
        GROUP BY t.id
        ORDER BY t.name
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/tags', methods=['POST'])
def create_tag():
    d = request.json
    name = (d.get('name') or '').strip().lower()
    if not name:
        return jsonify({'error':'name required'}), 400
    conn = get_db_connection()
    conn.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (name,))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'}), 201

@app.route('/api/tags/<int:id>', methods=['PUT'])
def update_tag(id):
    d = request.json
    name = (d.get('name') or '').strip().lower()
    conn = get_db_connection()
    conn.execute('UPDATE tags SET name=? WHERE id=?', (name, id))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

@app.route('/api/tags/<int:id>', methods=['DELETE'])
def delete_tag(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM tags WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

# ─── ACCOUNTS ────────────────────────────────────────────────────────────────

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT a.*,
               (SELECT MAX(date) FROM daily_reconciliation WHERE account_id = a.id) as last_recon_date,
               (SELECT MAX(date) FROM transactions WHERE account_id = a.id ) as last_import_date
        FROM accounts a
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/accounts/verify-integrity', methods=['POST'])
def verify_accounts_integrity():
    conn = db_module.get_db_connection()
    # Use the logic provided by the user
    rows = conn.execute('''
        SELECT 
            id, 
            name, 
            balance, 
            total_transfers, 
            total_balance,
            (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE account_id = a.id AND type = 'income') as income,
            (SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE account_id = a.id AND type = 'expense') as expenses,
            (SELECT COALESCE(SUM(raw_amount), 0) FROM transactions WHERE account_id = a.id AND type IN ('transfer_in', 'transfer_out')) as expected_transfers
        FROM accounts a
    ''').fetchall()
    
    results = []
    for r in rows:
        income = r['income']
        expenses = r['expenses']
        expected_balance = income - expenses
        expected_transfers = r['expected_transfers']
        expected_total = r['balance'] + expected_transfers
        
        results.append({
            "id": r['id'],
            "name": r['name'],
            "actual_balance": r['balance'],
            "expected_balance": expected_balance,
            "income": income,
            "expenses": expenses,
            "actual_transfers": r['total_transfers'],
            "expected_transfers": expected_transfers,
            "actual_total": r['total_balance'],
            "expected_total": expected_total,
            "balance_ok": r['balance'] == expected_balance,
            "transfers_ok": r['total_transfers'] == expected_transfers,
            "total_ok": r['total_balance'] == expected_total,
            "overall_ok": (r['balance'] == expected_balance and 
                           r['total_transfers'] == expected_transfers and 
                           r['total_balance'] == expected_total)
        })
    
    conn.close()
    return jsonify(results)

@app.route('/api/accounts', methods=['POST'])
def create_account():
    data = request.json
    conn = get_db_connection()
    conn.execute('INSERT INTO accounts (name, type, balance, institution, currency) VALUES (?, ?, ?, ?, ?)',
                 (data['name'], data['type'], int(round(float(data.get('balance', 0)))), data.get('institution'), data.get('currency', 'BRL')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 201

@app.route('/api/accounts/<int:id>', methods=['PUT'])
def update_account(id):
    data = request.json
    conn = get_db_connection()
    conn.execute('UPDATE accounts SET name=?, type=?, balance=?, institution=?, currency=? WHERE id=?',
                 (data['name'], data['type'], int(round(float(data.get('balance', 0)))), data.get('institution'), data.get('currency', 'BRL'), id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/accounts/<int:id>/sync', methods=['POST'])
def sync_account_balance(id):
    """Recalculate account balance based on transactions."""
    conn = get_db_connection()
    # sum transactions
    tx_sum = conn.execute('''
        SELECT SUM(CASE WHEN type='expense' THEN -amount ELSE amount END) 
        FROM transactions WHERE account_id=?
    ''', (id,)).fetchone()[0] or 0.0
    
    # Optional: adjust for investments if needed, but for now just transactions
    conn.execute('UPDATE accounts SET balance = ? WHERE id = ?', (tx_sum, id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'balance': tx_sum})

# ─── RECONCILIATION ──────────────────────────────────────────────────────────

@app.route('/api/reconciliation/<int:account_id>', methods=['GET'])
def get_account_reconciliation(account_id):
    from datetime import datetime
    date_from = request.args.get('date_from', f"{datetime.now().year}-01-01")
    date_to = request.args.get('date_to', f"{datetime.now().year}-12-31")
    ids_param = request.args.get('ids') # comma separated
    
    conn = get_db_connection()
    if ids_param:
        id_list = [int(i.strip()) for i in ids_param.split(',') if i.strip().isdigit()]
        placeholders = ','.join(['?'] * len(id_list))
        accounts = conn.execute(f'SELECT id, name FROM accounts WHERE id IN ({placeholders})', id_list).fetchall()
    elif account_id == 0:
        accounts = conn.execute('SELECT id, name FROM accounts').fetchall()
    else:
        accounts = conn.execute('SELECT id, name FROM accounts WHERE id=?', (account_id,)).fetchall()
    
    if not accounts:
        conn.close()
        return jsonify([])

    final_results = []
    from datetime import datetime, timedelta
    start_dt = datetime.strptime(date_from, '%Y-%m-%d')
    end_dt = datetime.strptime(date_to, '%Y-%m-%d')

    for account in accounts:
        acc_id = account['id']
        acc_name = account['name']
        
        # Balance today
        cur_bal = conn.execute('SELECT balance FROM accounts WHERE id=?', (acc_id,)).fetchone()
        current_balance = cur_bal['balance'] if cur_bal else 0.0
        
        txns = conn.execute('SELECT date, amount, type, raw_amount FROM transactions WHERE account_id=?', (acc_id,)).fetchall()
        
        ext = conn.execute('''
            SELECT date, external_balance, notes
            FROM daily_reconciliation
            WHERE account_id=? AND date BETWEEN ? AND ?
        ''', (acc_id, date_from, date_to)).fetchall()
        ext_map = {r['date']: r for r in ext}

        # ── Build baseline: start from today's balance and "undo" all
        #    transactions that fall within [date_from, today] to get the
        #    balance as it was at the START of date_from.
        #
        #    raw_amount is already signed:
        #      income       → +amount  (positive)
        #      expense      → -amount  (negative)
        #      transfer_in  → positive
        #      transfer_out → negative
        #      transfer     → signed as per CSV
        #      credit       → 0 effect on bank balance (card, not cash)
        #
        #    To "undo" a transaction: subtract its raw_amount from baseline.

        baseline = 0
        txns_by_date = {}

        for t in txns:
            txns_by_date.setdefault(t['date'], []).append(t)
            if t['date'] >= date_from and t['type'] != 'credit':
                baseline -= (t['raw_amount'] or 0)

        # ── Walk forward day by day from date_from to date_to,
        #    applying each day's transactions in chronological order.
        curr_walking_balance = baseline
        curr = start_dt
        while curr <= end_dt:
            d_str = curr.strftime('%Y-%m-%d')
            for t in txns_by_date.get(d_str, []):
                if t['type'] != 'credit':
                    curr_walking_balance += (t['raw_amount'] or 0)

            e = ext_map.get(d_str)
            final_results.append({
                'date': d_str,
                'account_id': acc_id,
                'account_name': acc_name,
                'platform_balance': round(curr_walking_balance, 2),
                'external_balance': e['external_balance'] if e else None,
                'notes': e['notes'] if e else None
            })
            curr += timedelta(days=1)

    conn.close()
    final_results.sort(key=lambda x: (x['date'], x['account_name']), reverse=True)
    return jsonify(final_results)


@app.route('/api/reconciliation', methods=['POST'])
def save_reconciliation():
    d = request.json
    conn = get_db_connection()
    ext_bal = int(round(float(d.get('external_balance', 0)))) if d.get('external_balance') is not None else None
    conn.execute('''
        INSERT INTO daily_reconciliation (account_id, date, external_balance, notes)
        VALUES (?,?,?,?)
        ON CONFLICT(account_id, date) DO UPDATE SET
            external_balance=excluded.external_balance,
            notes=excluded.notes,
            updated_at=datetime('now')
    ''', (d['account_id'], d['date'], ext_bal, d.get('notes')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/reconciliation/batch', methods=['POST'])
def save_batch_reconciliation():
    data_list = request.json  # list of {account_id, date, external_balance}
    conn = get_db_connection()
    for d in data_list:
        conn.execute('''
            INSERT INTO daily_reconciliation (account_id, date, external_balance, notes)
            VALUES (?,?,?,?)
            ON CONFLICT(account_id, date) DO UPDATE SET
                external_balance=excluded.external_balance,
                notes=excluded.notes,
                updated_at=datetime('now')
        ''', (d['account_id'], d['date'], d['external_balance'], d.get('notes')))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})
def delete_account(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM accounts WHERE id=?', (id,))
    conn.execute('DELETE FROM transactions WHERE account_id=?', (id,))
    conn.execute('DELETE FROM investments WHERE account_id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

# ─── TRANSACTIONS ─────────────────────────────────────────────────────────────

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    conn = get_db_connection()
    concil = request.args.get('conciliated')
    flags_q = request.args.get('flags')  # bit mask filter e.g. "2" for Risco
    query  = '''SELECT t.*, a.name as account_name, 
                       COALESCE(NULLIF(e.display_name, ''), e.name) as entity_name,
                       GROUP_CONCAT(tg.name) as tags,
                       ref.date as ref_date, ref.description as ref_description, ref.type as ref_type
                FROM transactions t
                LEFT JOIN accounts a ON t.account_id = a.id
                LEFT JOIN entities e ON t.entity_id = e.id
                LEFT JOIN transaction_tags tt ON tt.transaction_id = t.id
                LEFT JOIN tags tg ON tg.id = tt.tag_id
                LEFT JOIN transactions ref ON ref.id = t.transaction_ref_id
                WHERE (e.exclude_from_reports IS NULL OR e.exclude_from_reports = 0)'''
    params = []
    if concil == '1':
        query += ' AND (t.conciliation_status & 1) = 1'
    elif concil == '0':
        query += ' AND (t.conciliation_status & 1) = 0'
    if flags_q:
        query += f' AND (t.flags & {int(flags_q)}) = {int(flags_q)}'
    query += ' GROUP BY t.id ORDER BY t.date DESC, t.id desc'
    rows = conn.execute(query, params).fetchall()
    rules, enabled = _get_redaction_context(conn)
    conn.close()
    
    # Convert tags CSV to list and apply redaction
    result = []
    for r in rows:
        d = dict(r)
        d['tags'] = d['tags'].split(',') if d['tags'] else []
        d['description'] = _redact(d['description'], rules, enabled)
        d['notes'] = _redact(d['notes'], rules, enabled)
        d['entity_name'] = _redact(d['entity_name'], rules, enabled)
        result.append(d)
    return jsonify(result)

@app.route('/api/transactions', methods=['POST'])
def create_transaction():
    data = request.json
    conn = get_db_connection()
    amount = data.get('amount', 0)
    if amount is None:
        amount = 0
    amount = int(round(float(amount)))
    # Manual override for raw_amount if provided (cents)
    raw_amount = data.get('raw_amount')
    if raw_amount == '':
        raw_amount = 0
    if raw_amount is not None:
        raw_amount = int(round(float(raw_amount)))
    else:
        # Default auto-signing
        raw_amount = amount if data['type'] == 'income' else -amount
        
    if data['type'] in ['credit', 'transfer', 'transfer_in', 'transfer_out']:
        amount = 0
        
    if data['type'] in ['transfer', 'transfer_out']:
        raw_amount = -abs(raw_amount)
    elif data['type'] == 'transfer_in':
        raw_amount = abs(raw_amount)

    cur = conn.execute(
        'INSERT INTO transactions (account_id, date, description, category, amount, type, is_manual, notes, flags, recurring_id, entity_id, raw_description, raw_amount, liquidation_date, destination_account_id, metadata, transaction_ref_id) VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)',
        (data['account_id'], data['date'], data['description'], data.get('category'),
         amount, data['type'], data.get('notes'), data.get('flags', 0), 
         data.get('recurring_id'), data.get('entity_id'), data['description'], raw_amount, data.get('liquidation_date'), data.get('destination_account_id'),
         json.dumps(data['metadata']) if isinstance(data.get('metadata'), dict) else data.get('metadata'),
         data.get('transaction_ref_id') or None)
    )
    txn_id = cur.lastrowid
    _sync_tags(conn, 'transaction', txn_id, data.get('tags', []))
    if data['type'] == 'expense':
        conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (amount, data['account_id']))
    elif data['type'] == 'income':
        conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (amount, data['account_id']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'id': txn_id}), 201

@app.route('/api/transactions/<int:id>', methods=['PUT'])
def update_transaction(id):
    data = request.json
    conn = get_db_connection()
    old = conn.execute('SELECT * FROM transactions WHERE id=?', (id,)).fetchone()
    if old:
        if old['type'] == 'expense':
            conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (old['amount'], old['account_id']))
        elif old['type'] == 'income':
            conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (old['amount'], old['account_id']))

    amount = int(round(float(data.get('amount', 0))))
    # Manual override for raw_amount if provided (cents)
    raw_amount = data.get('raw_amount')
    if raw_amount == '':
        raw_amount = 0
    if raw_amount is not None:
        raw_amount = int(round(float(raw_amount)))
    else:
        # Auto-sign logic
        if amount != 0:
            raw_amount = amount if data['type'] == 'income' else -amount
        elif old['raw_amount'] != 0:
            raw_amount = old['raw_amount']
        else:
            raw_amount = 0

    if data['type'] in ['credit', 'transfer', 'transfer_in', 'transfer_out']:
        amount = 0
        if data['type'] in ['transfer', 'transfer_out']:
            raw_amount = -abs(raw_amount)
        elif data['type'] == 'transfer_in':
            raw_amount = abs(raw_amount)

    # Merge incoming metadata into existing (preserve import info, allow additions)
    existing_meta = {}
    if old:
        try:
            existing_meta = json.loads(old['metadata'] or '{}') if old['metadata'] else {}
        except Exception:
            existing_meta = {}
    incoming_meta = data.get('metadata') or {}
    if isinstance(incoming_meta, str):
        try: incoming_meta = json.loads(incoming_meta)
        except: incoming_meta = {}
    merged_meta = {**existing_meta, **incoming_meta}
    merged_meta_json = json.dumps(merged_meta, ensure_ascii=False) if merged_meta else None

    conn.execute(
        'UPDATE transactions SET account_id=?, date=?, description=?, category=?, amount=?, type=?, notes=?, flags=?, recurring_id=?, entity_id=?, conciliation_status=?, raw_description=?, raw_amount=?, liquidation_date=?, destination_account_id=?, metadata=?, transaction_ref_id=? WHERE id=?',
        (data['account_id'], data['date'], data['description'], data.get('category'),
         amount, data['type'], data.get('notes'), data.get('flags', 0),
         data.get('recurring_id'), data.get('entity_id'), data.get('conciliation_status', 0), data['description'], raw_amount, data.get('liquidation_date'), data.get('destination_account_id'), merged_meta_json,
         data.get('transaction_ref_id') or None, id)
    )
    _sync_tags(conn, 'transaction', id, data.get('tags', []))
    
    if data['type'] == 'expense':
        conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (amount, data['account_id']))
    elif data['type'] == 'income':
        conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (amount, data['account_id']))
    
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/transactions/<int:id>', methods=['DELETE'])
def delete_transaction(id):
    conn = get_db_connection()
    old = conn.execute('SELECT * FROM transactions WHERE id=?', (id,)).fetchone()
    if old:
        if old['type'] == 'expense':
            conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (old['amount'], old['account_id']))
        else:
            conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (old['amount'], old['account_id']))
        conn.execute('DELETE FROM transactions WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/transactions/<int:txn_id>/ref-candidates', methods=['GET'])
def get_ref_candidates(txn_id):
    """Return linkable transactions for a given transaction:
    - credit   -> expense transactions with category = credit_invoice_category
    - transfer_out -> transfer_in transactions (sorted by proximity in date)
    - transfer_in  -> transfer_out transactions (sorted by proximity in date)
    """
    conn = get_db_connection()
    txn = conn.execute('SELECT * FROM transactions WHERE id=?', (txn_id,)).fetchone()
    if not txn:
        conn.close()
        return jsonify([])

    txn = dict(txn)
    txn_type = txn.get('type', '')

    rows = []
    if txn_type == 'credit':
        cfg_row = conn.execute("SELECT value FROM system_config WHERE key='credit_invoice_category'").fetchone()
        inv_cat = cfg_row['value'] if cfg_row else 'Fatura Cartão'
        rows = conn.execute(
            '''SELECT t.id, t.date, t.description, t.amount, t.raw_amount, t.type, t.category, t.account_id,
                      a.name as account_name
               FROM transactions t LEFT JOIN accounts a ON a.id = t.account_id
               WHERE t.category = ? AND t.id != ? AND t.type = 'expense'
               ORDER BY t.date DESC LIMIT 200''',
            (inv_cat, txn_id)
        ).fetchall()
    elif txn_type in ('transfer_out', 'transfer_in'):
        target_type = 'transfer_in' if txn_type == 'transfer_out' else 'transfer_out'
        rows = conn.execute(
            '''SELECT t.id, t.date, t.description, t.amount, t.raw_amount, t.type, t.category, t.account_id,
                      a.name as account_name
               FROM transactions t LEFT JOIN accounts a ON a.id = t.account_id
               WHERE t.type = ? AND t.id != ?
               ORDER BY ABS(julianday(t.date) - julianday(?)) ASC, t.id DESC LIMIT 200''',
            (target_type, txn_id, txn.get('date', ''))
        ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/transactions/<int:id>/reconcile', methods=['PATCH'])
def reconcile_transaction(id):
    """Toggle bit 1 (manual reconciliation) on conciliation_status."""
    conn = get_db_connection()
    row = conn.execute('SELECT conciliation_status FROM transactions WHERE id=?', (id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    new_status = row['conciliation_status'] ^ 1   # toggle bit 1
    conn.execute('UPDATE transactions SET conciliation_status=? WHERE id=?', (new_status, id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'conciliation_status': new_status})


@app.route('/api/transactions/<int:id>/link-ref', methods=['PATCH'])
def link_ref_transaction(id):
    """Bidirectionally link two transactions via transaction_ref_id.
    Body: { "ref_id": <other_id> | null }
    When ref_id is provided, sets t.transaction_ref_id = ref_id AND ref.transaction_ref_id = id.
    When ref_id is null, clears both sides.
    """
    data = request.get_json()
    ref_id = data.get('ref_id')  # may be None (unlink)
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT id FROM transactions WHERE id=?', (id,)).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'Transaction not found'}), 404

        if ref_id is None:
            # Unlink: clear both sides
            old_ref = conn.execute('SELECT transaction_ref_id FROM transactions WHERE id=?', (id,)).fetchone()
            conn.execute('UPDATE transactions SET transaction_ref_id=NULL WHERE id=?', (id,))
            if old_ref and old_ref['transaction_ref_id']:
                conn.execute('UPDATE transactions SET transaction_ref_id=NULL WHERE id=? AND transaction_ref_id=?',
                             (old_ref['transaction_ref_id'], id))
        else:
            ref_row = conn.execute('SELECT id FROM transactions WHERE id=?', (ref_id,)).fetchone()
            if not ref_row:
                return jsonify({'status': 'error', 'message': 'Referenced transaction not found'}), 404
            # Clear previous backlinks on both
            old_self = conn.execute('SELECT transaction_ref_id FROM transactions WHERE id=?', (id,)).fetchone()
            old_other = conn.execute('SELECT transaction_ref_id FROM transactions WHERE id=?', (ref_id,)).fetchone()
            if old_self and old_self['transaction_ref_id'] and old_self['transaction_ref_id'] != ref_id:
                conn.execute('UPDATE transactions SET transaction_ref_id=NULL WHERE id=?', (old_self['transaction_ref_id'],))
            if old_other and old_other['transaction_ref_id'] and old_other['transaction_ref_id'] != id:
                conn.execute('UPDATE transactions SET transaction_ref_id=NULL WHERE id=?', (old_other['transaction_ref_id'],))
            # Set both sides
            conn.execute('UPDATE transactions SET transaction_ref_id=? WHERE id=?', (ref_id, id))
            conn.execute('UPDATE transactions SET transaction_ref_id=? WHERE id=?', (id, ref_id))

        conn.commit()
        return jsonify({'status': 'success'})
    finally:
        conn.close()

# ─── INVESTMENTS ──────────────────────────────────────────────────────────────

@app.route('/api/investments', methods=['GET'])
def get_investments():
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM investments').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/investments', methods=['POST'])
def create_investment():
    data = request.json
    conn = get_db_connection()
    amount = float(data.get('amount', 0))
    pp = int(round(float(data.get('purchase_price', 0))))
    cp = int(round(float(data.get('current_price', pp))))
    conn.execute('INSERT INTO investments (account_id, name, type, amount, purchase_price, current_price, date) VALUES (?,?,?,?,?,?,?)',
                 (data.get('account_id'), data['name'], data['type'], amount*100, pp, cp, data['date']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 201

@app.route('/api/investments/<int:id>', methods=['PUT'])
def update_investment(id):
    data = request.json
    conn = get_db_connection()
    amount = float(data.get('amount', 0))
    pp = int(round(float(data.get('purchase_price', 0))))
    cp = int(round(float(data.get('current_price', pp))))
    conn.execute('UPDATE investments SET account_id=?, name=?, type=?, amount=?, purchase_price=?, current_price=?, date=? WHERE id=?',
                 (data.get('account_id'), data['name'], data['type'], amount, pp, cp, data['date'], id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/investments/<int:id>', methods=['DELETE'])
def delete_investment(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM investments WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

# ─── ENTITIES ────────────────────────────────────────────────────────────────

@app.route('/api/entities', methods=['GET'])
def get_entities():
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT 
            COALESCE(NULLIF(e.display_name, ''), e.name) as name, 
            e.*,
            e.name as legal_name,
            COUNT(t.id) as transaction_count,
            COALESCE(SUM(CASE WHEN t.type='expense' THEN t.amount ELSE 0 END), 0) as total_spent,
            COALESCE(SUM(CASE WHEN t.type='income'  THEN t.amount ELSE 0 END), 0) as total_received,
            MAX(t.date) as last_activity
        FROM entities e
        LEFT JOIN transactions t ON t.entity_id = e.id
        GROUP BY e.id
        ORDER BY name
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/entities', methods=['POST'])
def create_entity():
    data = request.json
    conn = get_db_connection()
    if data.get('legal_name'):
       data['name'] = data['legal_name']
    cur = conn.execute(
        'INSERT INTO entities (name, type, document, bank, notes, display_name, exclude_from_reports) VALUES (?,?,?,?,?,?,?)',
        (data['name'], data.get('type','company'), data.get('document',''), data.get('bank',''), 
         data.get('notes',''), data.get('display_name',''), int(data.get('exclude_from_reports', 0)))
    )
    eid = cur.lastrowid
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'id': eid}), 201

@app.route('/api/entities/<int:id>', methods=['PUT'])
def update_entity(id):
    data = request.json
    conn = get_db_connection()
    if data.get('legal_name'):
       data['name'] = data['legal_name']
    conn.execute(
        'UPDATE entities SET name=?, type=?, document=?, bank=?, notes=?, flags=?, original_entity_id=?, display_name=?, exclude_from_reports=? WHERE id=?',
        (data['name'], data.get('type','company'), data.get('document',''), data.get('bank',''),
         data.get('notes',''), data.get('flags', 0), data.get('original_entity_id'), 
         data.get('display_name',''), int(data.get('exclude_from_reports', 0)), id)
    )
    _sync_tags(conn, 'entity', id, data.get('tags', []))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/entities/<int:id>', methods=['DELETE'])
def delete_entity(id):
    conn = get_db_connection()
    conn.execute('UPDATE transactions SET entity_id=NULL WHERE entity_id=?', (id,))
    conn.execute('DELETE FROM entities WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/entities/<int:id>/transactions', methods=['GET'])
def entity_transactions(id):
    conn = get_db_connection()
    query  = '''SELECT t.*, a.name as account_name, 
                       COALESCE(NULLIF(e.display_name, ''), e.name) as entity_name,
                       GROUP_CONCAT(tg.name) as tags
                FROM transactions t
                LEFT JOIN accounts a ON t.account_id=a.id
                LEFT JOIN entities e ON t.entity_id=e.id
                LEFT JOIN transaction_tags tt ON tt.transaction_id=t.id
                LEFT JOIN tags tg ON tg.id=tt.tag_id
                WHERE t.entity_id=? 
                  AND (e.exclude_from_reports IS NULL OR e.exclude_from_reports = 0)
                GROUP BY t.id ORDER BY t.date DESC'''
    rows = conn.execute(query, (id,)).fetchall()
    rules, enabled = _get_redaction_context(conn)
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d['tags'] = d['tags'].split(',') if d['tags'] else []
        d['description'] = _redact(d['description'], rules, enabled)
        d['notes'] = _redact(d['notes'], rules, enabled)
        result.append(d)
    return jsonify(result)

def _resolve_entity(conn, entity_id):
    """Follow original_entity_id chain and return the canonical entity id."""
    visited = set()
    current = entity_id
    while current and current not in visited:
        visited.add(current)
        row = conn.execute('SELECT original_entity_id FROM entities WHERE id=?', (current,)).fetchone()
        if row and row['original_entity_id']:
            current = row['original_entity_id']
        else:
            break
    return current

def _find_or_create_entity(conn, name, etype, document, bank):
    """Return (canonical_entity_id, raw_entity_id) — raw differs if entity has a parent."""
    if not name:
        return None, None
    row = conn.execute('SELECT id, original_entity_id FROM entities WHERE LOWER(name)=LOWER(?)', (name,)).fetchone()
    if row:
        raw_id = row['id']
        canonical_id = _resolve_entity(conn, raw_id)
        return canonical_id, (raw_id if canonical_id != raw_id else None)
    # Create new entity
    cur = conn.execute(
        'INSERT INTO entities (name, type, document, bank) VALUES (?,?,?,?)',
        (name, etype or 'company', document or '', bank or '')
    )
    new_id = cur.lastrowid
    return new_id, None

# ─── ENTITY MERGE ─────────────────────────────────────────────────────────────

@app.route('/api/entities/<int:id>/merge', methods=['POST'])
def merge_entity(id):
    """Merge entity `id` into `target_id`: move all transactions, set original_entity_id."""
    data = request.json
    target_id = data.get('target_id')
    if not target_id or target_id == id:
        return jsonify({'status': 'error', 'message': 'target_id inválido'}), 400
    conn = get_db_connection()
    # Move transactions: entity_id → target, raw_entity_id = id (the original)
    conn.execute('''
        UPDATE transactions
        SET entity_id = ?, raw_entity_id = COALESCE(raw_entity_id, entity_id)
        WHERE entity_id = ?
    ''', (target_id, id))
    # Mark entity as merged
    conn.execute('UPDATE entities SET original_entity_id=? WHERE id=?', (target_id, id))
    conn.commit()
    moved = conn.execute('SELECT changes()').fetchone()[0]
    conn.close()
    return jsonify({'status': 'success', 'moved': moved})


# ─── IMPORT ───────────────────────────────────────────────────────────────────

@app.route('/api/import/profiles', methods=['GET'])
def get_import_profiles():
    from parsers import get_profiles
    return jsonify(get_profiles())

@app.route('/api/import/preview', methods=['POST'])
def import_preview():
    from parsers import get_csv_preview
    file = request.files.get('file')
    if not file: return jsonify({'error': 'Arquivo não enviado'}), 400
    res = get_csv_preview(file.read())
    return jsonify(res)

@app.route('/api/import', methods=['POST'])
def import_statement():
    from parsers import parse_csv_statement, PROFILES
    file = request.files.get('file')
    account_id = request.form.get('account_id')
    bank = request.form.get('bank', 'generic')
    print(f"Banco recebido: '{bank}'")
    mapping_str = request.form.get('mapping') # e.g. JSON string

    if not file or not account_id:
        return jsonify({'status': 'error', 'message': 'Arquivo ou conta não informados'}), 400

    # Handle custom mapping if provided
    if mapping_str and bank == 'custom':
        mapping = json.loads(mapping_str)
        # We simulate a profile
        custom_profile = {
            "label": "Custom",
            "date_col": mapping.get('date_col'),
            "amount_col": mapping.get('amount_col'),
            "desc_col": mapping.get('desc_col'),
            "cat_col": mapping.get('cat_col'),
            "uid_col": mapping.get('uid_col'),
            "encoding": "utf-8",
            "delimiter": mapping.get('delimiter', ',')
        }
        # Injects profile temporarily or use a different function
        # Actually parse_csv_statement always look into PROFILES.
        # Let's temporarily add to PROFILES or just pass it?
        # Actually PROFILES is a dict. Let's update it.
        PROFILES['custom'] = custom_profile
        
    file_bytes_read = file.read()
    # Compute MD5 of imported file for traceability
    import_md5 = hashlib.md5(file_bytes_read).hexdigest()
    import_filename = file.filename or 'unknown'
    import_metadata_json = json.dumps({
        'source_file': import_filename,
        'source_md5': import_md5,
        'bank_profile': bank,
        'imported_at': datetime.now(timezone.utc).isoformat() + 'Z'
    }, ensure_ascii=False)

    result = parse_csv_statement(file_bytes_read, bank=bank)
    transactions = result.get('transactions', [])
    ignored_parse = result.get('ignored', [])

    conn = get_db_connection()
    count = 0
    duplicate_lines = []
    
    is_credit = request.form.get('type') == 'credit'
    file_bytes_for_import = file_bytes_read  # already read above

    for t in transactions:
        uid = t.get('external_uid')
        raw_uid = t.get('raw_external_uid')
        line = t.get('line')
        if uid:
            existing = conn.execute(
                'SELECT id, account_id FROM transactions WHERE external_uid=?',
                (uid,)
            ).fetchone()
            if existing:
                duplicate_lines.append(f"{line}({raw_uid} -> {t})")
                continue

        # Auto-create / find entity (now returns tuple)
        entity_id, raw_entity_id = _find_or_create_entity(
            conn,
            t.get('entity_name', ''),
            t.get('entity_type', 'company'),
            t.get('entity_document', ''),
            t.get('entity_bank', ''),
        )

        amount = t['amount']
        txn_type = t['type']
        # Sign the raw_amount based on original input type
        raw_amount = amount if txn_type == 'income' else -amount
        
        if is_credit or txn_type == 'transfer':
            if is_credit: txn_type = 'credit'
            amount = 0

        conn.execute(
            'INSERT INTO transactions (account_id, date, description, category, amount, type, is_manual, external_uid, entity_id, raw_entity_id, raw_external_uid, raw_description, raw_amount, metadata) VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?)',
            (account_id, t['date'], t['description'], t['category'], amount, txn_type, uid, entity_id, raw_entity_id, raw_uid, t['description'], raw_amount, import_metadata_json)
        )
        if txn_type == 'expense':
            conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (amount, account_id))
        elif txn_type == 'income':
            conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (amount, account_id))
        count += 1

    conn.commit()
    conn.close()

    msg = f'{count} transações importadas'
    details = []
    if duplicate_lines:
        details.append(f'Duplicadas: {", ".join(map(str, duplicate_lines))}')
    if ignored_parse:
        lines = [str(x["line"]) for x in ignored_parse]
        details.append(f'Inválidas: {", ".join(lines)}')
        
    if details:
        msg += " (" + "; ".join(details) + ")"
        
    return jsonify({
        'status': 'success', 
        'message': msg, 
        'imported': count, 
        'duplicates': len(duplicate_lines),
        'invalid': len(ignored_parse)
    })


# ─── PROCESSAR ARQUIVOS ────────────────────────────────────────────────────────

def _ensure_file_imports_table(conn):
    """Create the file_imports log table if it doesn't exist."""
    conn.execute('''
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
    ''')
    conn.commit()


def _file_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


@app.route('/api/files', methods=['GET'])
def list_enc_files():
    """List .csv.enc files in FILES_DIRECTORY, marking already-processed ones."""
    conn = get_db_connection()
    _ensure_file_imports_table(conn)

    # All processed md5s for this database
    processed = {r['md5'] for r in conn.execute('SELECT md5 FROM file_imports').fetchall()}
    conn.close()

    files_dir = FILES_DIRECTORY
    result = []
    if os.path.isdir(files_dir):
        for root, _dirs, fnames in os.walk(files_dir):
            for fname in sorted(fnames):
                if not fname.endswith('.csv.enc'):
                    continue
                fpath = os.path.join(root, fname)
                # Relative path from FILES_DIRECTORY (e.g. "subpasta/arquivo.csv.enc")
                rel = os.path.relpath(fpath, files_dir)
                try:
                    md5   = _file_md5(fpath)
                    size  = os.path.getsize(fpath)
                    mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat()
                except OSError:
                    continue
                result.append({
                    'filename':          rel,      # relative path used as identifier
                    'path':              fpath,
                    'md5':               md5,
                    'size':              size,
                    'modified_at':       mtime,
                    'already_processed': md5 in processed,
                })

    return jsonify(result)


@app.route('/api/files/log', methods=['GET'])
def list_file_import_logs():
    """Return the full processing log for this database."""
    conn = get_db_connection()
    _ensure_file_imports_table(conn)
    rows = [dict(r) for r in conn.execute(
        'SELECT * FROM file_imports ORDER BY processed_at DESC'
    ).fetchall()]
    conn.close()
    return jsonify(rows)


@app.route('/api/files/sync', methods=['POST'])
def sync_files():
    """
    Triggers the sync via the HTTP endpoint defined in SYNC_FILE_API.
    """
    sync_api = os.environ.get('SYNC_FILE_API')
    if not sync_api:
        return jsonify({'error': 'SYNC_FILE_API environment variable not set'}), 500

    if not sync_api.startswith('http'):
        return jsonify({'error': f'Invalid SYNC_FILE_API format: {sync_api}. Expected http://...'}), 500

    import urllib.request
    try:
        with urllib.request.urlopen(sync_api, timeout=60.0) as response:
            data = response.read().decode('utf-8')
            return jsonify({'status': 'ok', 'output': data})
    except Exception as e:
        return jsonify({'error': f'Sync API error: {str(e)}'}), 500


@app.route('/api/files/process', methods=['POST'])
def process_enc_files():
    """
    Process one or more .csv.enc files from FILES_DIRECTORY.

    Body JSON:
    {
      "files":      ["statement_jan.csv.enc", ...],
      "bank":       "nubank",
      "account_id": 3,
      "type":       "debit"   // optional, "credit" for credit cards
    }

    The .csv.enc files are expected to be plain CSV with the .enc extension
    (the extension signals they came from a secure source; decryption is
    app-level if needed — for now we just read them as-is).
    """
    from parsers import parse_csv_statement, PROFILES

    data       = request.json or {}
    filenames  = data.get('files', [])
    bank       = data.get('bank', 'generic')
    account_id = data.get('account_id')
    is_credit  = data.get('type') == 'credit'

    if not filenames:
        return jsonify({'error': 'Nenhum arquivo informado'}), 400
    if not account_id:
        return jsonify({'error': 'account_id é obrigatório'}), 400

    conn = get_db_connection()
    _ensure_file_imports_table(conn)

    summary = []

    for fname in filenames:
        # Security: normalise and ensure path stays inside FILES_DIRECTORY
        fpath = os.path.realpath(os.path.join(FILES_DIRECTORY, fname))
        if not fpath.startswith(os.path.realpath(FILES_DIRECTORY) + os.sep):
            summary.append({'filename': fname, 'error': 'Caminho inválido'})
            continue
        if not fpath.endswith('.csv.enc'):
            summary.append({'filename': fname, 'error': 'Extensão inválida'})
            continue
        if not os.path.exists(fpath):
            summary.append({'filename': fname, 'error': 'Arquivo não encontrado'})
            continue


        md5 = _file_md5(fpath)

        # Check if already processed in this DB
        existing = conn.execute('SELECT id FROM file_imports WHERE md5=?', (md5,)).fetchone()
        if existing:
            summary.append({'filename': fname, 'status': 'skipped', 'reason': 'already_processed', 'md5': md5})
            continue

        with open(fpath, 'rb') as f:
            raw_bytes = f.read()

        # Decrypt AES-GCM (IV 12 bytes || ciphertext+tag)
        try:
            file_bytes = _decrypt_enc_bytes(raw_bytes)
        except ValueError as exc:
            summary.append({'filename': fname, 'status': 'error', 'error': str(exc)})
            continue

        result        = parse_csv_statement(file_bytes, bank=bank)
        transactions  = result.get('transactions', [])
        ignored_parse = result.get('ignored', [])


        count          = 0
        duplicate_lines = []
        import_metadata = json.dumps({
            'source_file': fname,
            'source_md5':  md5,
            'bank_profile': bank,
            'imported_at':  datetime.now(timezone.utc).isoformat() + 'Z',
        }, ensure_ascii=False)

        for t in transactions:
            uid      = t.get('external_uid')
            raw_uid  = t.get('raw_external_uid')
            line     = t.get('line')

            if uid:
                # Deduplication logic: check if this transaction (same external UID)
                # already exists in this account. (Cross-account duplicates are potentially allowed
                # for transfers, but within the same account it's almost always an error)
                # Note: changed to search ANY account to be more restrictive as per user requirement.
                dup = conn.execute(
                    'SELECT id, account_id FROM transactions WHERE external_uid=?',
                    (uid,)
                ).fetchone()
                if dup:
                    duplicate_lines.append(line)
                    continue

            entity_id, raw_entity_id = _find_or_create_entity(
                conn,
                t.get('entity_name', ''),
                t.get('entity_type', 'company'),
                t.get('entity_document', ''),
                t.get('entity_bank', ''),
            )

            amount   = t['amount']
            txn_type = t['type']
            raw_amount = amount if txn_type == 'income' else -amount

            if is_credit:
                txn_type = 'credit'
                amount   = 0

            conn.execute(
                'INSERT INTO transactions '
                '(account_id, date, description, category, amount, type, is_manual, '
                'external_uid, entity_id, raw_entity_id, raw_external_uid, '
                'raw_description, raw_amount, metadata) '
                'VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?,?)',
                (account_id, t['date'], t['description'], t['category'],
                 amount, txn_type, uid, entity_id, raw_entity_id,
                 raw_uid, t['description'], raw_amount, import_metadata)
            )
            if txn_type == 'expense':
                conn.execute('UPDATE accounts SET balance = balance - ? WHERE id=?', (amount, account_id))
            elif txn_type == 'income':
                conn.execute('UPDATE accounts SET balance = balance + ? WHERE id=?', (amount, account_id))
            count += 1

        # Record in log
        conn.execute(
            'INSERT INTO file_imports (filename, md5, bank, account_id, imported, duplicates, invalid) '
            'VALUES (?,?,?,?,?,?,?)',
            (fname, md5, bank, account_id, count, len(duplicate_lines), len(ignored_parse))
        )
        conn.commit()

        summary.append({
            'filename': fname,
            'md5':      md5,
            'status':   'ok',
            'imported': count,
            'duplicates': len(duplicate_lines),
            'invalid':    len(ignored_parse),
        })

    conn.close()
    return jsonify({'results': summary})


# ─── REPORTS ──────────────────────────────────────────────────────────────────


@app.route('/api/reports', methods=['GET'])
def get_reports():
    conn = get_db_connection()

    # Monthly cashflow — last 12 months (include transfer and credit via raw_amount)
    monthly = conn.execute('''
        SELECT strftime('%Y-%m', date) as month,
               SUM(CASE 
                    WHEN type='income' THEN amount 
                    WHEN type='transfer' AND raw_amount > 0 THEN raw_amount
                    ELSE 0 END) as income,
               SUM(CASE 
                    WHEN type='expense' THEN amount 
                    WHEN type='transfer' AND raw_amount < 0 THEN -raw_amount
                    WHEN type='credit' THEN -raw_amount
                    ELSE 0 END) as expense
        FROM transactions
        WHERE date >= date('now', '-12 months')
        GROUP BY month ORDER BY month
    ''').fetchall()

    # Category breakdown (all time)
    categories = conn.execute('''
        SELECT category, COUNT(*) as count,
               SUM(amount) as total
        FROM transactions WHERE type='expense' AND category IS NOT NULL
        GROUP BY category ORDER BY total DESC LIMIT 12
    ''').fetchall()

    # Top entities by spending
    top_entities = conn.execute('''
        SELECT e.name, e.type,
               COUNT(t.id) as count,
               SUM(t.amount) as total
        FROM entities e
        JOIN transactions t ON t.entity_id = e.id AND t.type='expense'
        GROUP BY e.id ORDER BY total DESC LIMIT 10
    ''').fetchall()

    # Top entities by receiving
    top_senders = conn.execute('''
        SELECT e.name, e.type,
               COUNT(t.id) as count,
               SUM(t.amount) as total
        FROM entities e
        JOIN transactions t ON t.entity_id = e.id AND t.type='income'
        GROUP BY e.id ORDER BY total DESC LIMIT 5
    ''').fetchall()

    # Biggest single transactions
    biggest = conn.execute('''
        SELECT t.date, t.description, t.category, t.amount, t.type,
               a.name as account_name, e.name as entity_name
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.id
        LEFT JOIN entities e ON t.entity_id = e.id
        ORDER BY t.amount DESC LIMIT 10
    ''').fetchall()

    # Investment performance
    investments = conn.execute('''
        SELECT type,
               COUNT(*) as count,
               SUM(amount * purchase_price) as total_invested,
               SUM(amount * current_price) as total_current
        FROM investments
        GROUP BY type
    ''').fetchall()

    # Overall KPIs
    kpis = conn.execute('''
        SELECT
            SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as total_income,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as total_expense,
            COUNT(*) as total_transactions,
            MIN(date) as first_date,
            MAX(date) as last_date
        FROM transactions
    ''').fetchone()

    # Account balances
    accounts = conn.execute('SELECT name, type, balance FROM accounts ORDER BY balance DESC').fetchall()

    # ── NEW DATASETS ─────────────────────────────────────────────────────────

    # Spending by weekday (0=Sun … 6=Sat)
    WEEKDAYS = ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb']
    weekday_rows = conn.execute('''
        SELECT CAST(strftime('%w', date) AS INTEGER) as wd,
               SUM(amount) as total, COUNT(*) as count
        FROM transactions WHERE type='expense'
        GROUP BY wd ORDER BY wd
    ''').fetchall()
    weekday_spending = [
        {'weekday': WEEKDAYS[r['wd']], 'total': r['total'], 'count': r['count']}
        for r in weekday_rows
    ]

    # Year-over-year comparison (current year vs previous year, by month)
    yoy = conn.execute('''
        SELECT strftime('%m', date) as month,
               SUM(CASE WHEN strftime('%Y',date)=strftime('%Y','now') AND type='expense' THEN amount ELSE 0 END) as curr_expense,
               SUM(CASE WHEN strftime('%Y',date)=strftime('%Y','now') AND type='income' THEN amount ELSE 0 END) as curr_income,
               SUM(CASE WHEN strftime('%Y',date)=cast(strftime('%Y','now') as integer)-1 AND type='expense' THEN amount ELSE 0 END) as prev_expense,
               SUM(CASE WHEN strftime('%Y',date)=cast(strftime('%Y','now') as integer)-1 AND type='income' THEN amount ELSE 0 END) as prev_income
        FROM transactions
        WHERE strftime('%Y',date) IN (strftime('%Y','now'), cast(cast(strftime('%Y','now') as integer)-1 as text))
        GROUP BY month ORDER BY month
    ''').fetchall()
    MONTH_LABELS = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez']
    yearly_comparison = [
        {'month': MONTH_LABELS[int(r['month'])-1],
         'curr_expense': r['curr_expense'], 'curr_income': r['curr_income'],
         'prev_expense': r['prev_expense'], 'prev_income': r['prev_income']}
        for r in yoy
    ]

    # Category trend — last 6 months, top 5 categories as columns
    top5_cats = [r['category'] for r in conn.execute('''
        SELECT category FROM transactions
        WHERE type='expense' AND category IS NOT NULL
          AND date >= date('now','-6 months')
        GROUP BY category ORDER BY SUM(amount) DESC LIMIT 5
    ''').fetchall()]
    cat_trend_rows = conn.execute('''
        SELECT strftime('%Y-%m', date) as month, category,
               SUM(amount) as total
        FROM transactions
        WHERE type='expense' AND category IN ({})
          AND date >= date('now','-6 months')
        GROUP BY month, category ORDER BY month
    '''.format(','.join('?' for _ in top5_cats)), top5_cats).fetchall() if top5_cats else []
    # Pivot into month → {cat: total}
    ct_map = {}
    for r in cat_trend_rows:
        ct_map.setdefault(r['month'], {})
        ct_map[r['month']][r['category']] = r['total']
    category_trend = [
        {'month': m, **{c: ct_map[m].get(c, 0) for c in top5_cats}}
        for m in sorted(ct_map)
    ]

    # monthly savings rate (last 12 months)
    savings_rate = [
        {**dict(m), 'rate': round((m['income'] - m['expense']) / m['income'] * 100, 1) if m['income'] > 0 else 0}
        for m in [dict(r) for r in monthly]
    ]

    # Net worth snapshot (total accounts + total investments)
    inv_total = conn.execute(
        'SELECT COALESCE(SUM(amount * current_price),0) as val FROM investments'
    ).fetchone()['val']
    acc_total = conn.execute(
        'SELECT COALESCE(SUM(balance),0) as val FROM accounts'
    ).fetchone()['val']

    conn.close()

    return jsonify({
        'monthly_cashflow':    [dict(r) for r in monthly],
        'categories':          [dict(r) for r in categories],
        'top_entities_spending':  [dict(r) for r in top_entities],
        'top_entities_receiving': [dict(r) for r in top_senders],
        'biggest_transactions':   [dict(r) for r in biggest],
        'investments':            [dict(r) for r in investments],
        'kpis':                   dict(kpis) if kpis else {},
        'accounts':               [dict(r) for r in accounts],
        'weekday_spending':       weekday_spending,
        'yearly_comparison':      yearly_comparison,
        'category_trend':         category_trend,
        'category_trend_keys':    top5_cats,
        'savings_rate':           savings_rate,
        'net_worth': {'accounts': acc_total, 'investments': inv_total, 'total': acc_total + inv_total},
    })


# ─── GLOBAL SEARCH ────────────────────────────────────────────────────────────


def _parse_br_date(s):
    """Convert DD/MM/YYYY → YYYY-MM-DD for SQLite, or None on failure."""
    try:
        return datetime.strptime(s.strip(), '%d/%m/%Y').strftime('%Y-%m-%d')
    except Exception:
        return None

def _parse_smart_query(q):
    """
    Returns a dict with ONE active mode:
      {'mode':'id',    'id': int}
      {'mode':'amount','op':str, 'val':float}
      {'mode':'date',  'type':'exact'|'range', 'd1':str, 'd2':str|None}
      {'mode':'text',  'q':str}
    Operators recognized:
      #123                             → id lookup
      >10, >=10, <50, <=50, =50        → amount
      01/01/2025                       → exact date (Brazilian format)
      01/01/2025-31/12/2025            → date range
    """
    q = q.strip()

    # #ID
    m = _re.match(r'^#(\d+)$', q)
    if m:
        return {'mode': 'id', 'id': int(m.group(1))}

    # Amount operator
    m = _re.match(r'^([><=]{1,2})\s*(\d+(?:[.,]\d+)?)$', q)
    if m:
        op  = m.group(1)
        val = float(m.group(2).replace(',', '.'))
        return {'mode': 'amount', 'op': op, 'val': val}

    # Date range DD/MM/YYYY-DD/MM/YYYY  (dash allowed with spaces)
    m = _re.match(r'^(\d{2}/\d{2}/\d{4})\s*-\s*(\d{2}/\d{2}/\d{4})$', q)
    if m:
        d1 = _parse_br_date(m.group(1))
        d2 = _parse_br_date(m.group(2))
        if d1 and d2:
            return {'mode': 'date', 'type': 'range', 'd1': min(d1,d2), 'd2': max(d1,d2)}

    # Exact date DD/MM/YYYY
    m = _re.match(r'^(\d{2}/\d{2}/\d{4})$', q)
    if m:
        d = _parse_br_date(m.group(1))
        if d:
            return {'mode': 'date', 'type': 'exact', 'd1': d, 'd2': d}

    return {'mode': 'text', 'q': q}


@app.route('/api/search', methods=['GET'])
def global_search():
    raw_q = request.args.get('q', '').strip()
    if len(raw_q) < 1:
        return jsonify([])

    parsed = _parse_smart_query(raw_q)
    conn   = get_db_connection()
    results = []

    TXN_SELECT = '''
        SELECT t.id, t.date, t.description, t.category, t.amount, t.type,
               t.conciliation_status, a.name as account_name, e.name as entity_name
        FROM transactions t
        LEFT JOIN accounts a ON t.account_id = a.id
        LEFT JOIN entities e ON t.entity_id = e.id
    '''
    ENT_SELECT = 'SELECT id, name, type, document, bank FROM entities'

    mode = parsed['mode']

    if mode == 'id':
        txns = conn.execute(TXN_SELECT + ' WHERE t.id = ?', (parsed['id'],)).fetchall()
        ents = conn.execute(ENT_SELECT + ' WHERE id = ?', (parsed['id'],)).fetchall()

    elif mode == 'amount':
        op_map = {'>': '>', '>=': '>=', '<': '<', '<=': '<=', '=': '='}
        op = op_map.get(parsed['op'], '=')
        txns = conn.execute(
            TXN_SELECT + f' WHERE t.amount {op} ? ORDER BY t.date DESC LIMIT 20',
            (parsed['val'],)
        ).fetchall()
        ents = []

    elif mode == 'date':
        txns = conn.execute(
            TXN_SELECT + ' WHERE t.date BETWEEN ? AND ? ORDER BY t.date DESC LIMIT 20',
            (parsed['d1'], parsed['d2'])
        ).fetchall()
        ents = []

    else:  # text
        like = f'%{parsed["q"]}%'
        txns = conn.execute(
            TXN_SELECT + '''
            WHERE t.description LIKE ?
               OR t.category    LIKE ?
               OR CAST(t.amount AS TEXT) LIKE ?
               OR t.date LIKE ?
               OR e.name LIKE ?
            ORDER BY t.date DESC LIMIT 15
            ''', (like, like, like, like, like)
        ).fetchall()
        ents = conn.execute(
            ENT_SELECT + ' WHERE name LIKE ? OR document LIKE ? OR bank LIKE ? LIMIT 8',
            (like, like, like)
        ).fetchall()

    for r in txns:
        results.append({'kind': 'transaction', **dict(r)})
    for r in ents:
        results.append({'kind': 'entity', **dict(r)})

    conn.close()
    return jsonify(results)




# ─── RECURRING EXPENSES ───────────────────────────────────────────────────────

@app.route('/api/recurring', methods=['GET'])
def get_recurring():
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT r.*, a.name as account_name, 
               COALESCE(NULLIF(e.display_name, ''), e.name) as entity_name
        FROM recurring_expenses r
        LEFT JOIN accounts a ON r.account_id=a.id
        LEFT JOIN entities e ON r.entity_id=e.id
        ORDER BY r.next_date
    ''').fetchall()
    rules, enabled = _get_redaction_context(conn)
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        d['name'] = _redact(d['name'], rules, enabled)
        d['notes'] = _redact(d['notes'], rules, enabled)
        d['entity_name'] = _redact(d['entity_name'], rules, enabled)
        result.append(d)
    return jsonify(result)

def _generate_pretxns_for_recurring(conn, recurr_id, recurr):
    """Generate pending pre-transactions for the next 3 occurrences of a recurring."""
    from datetime import date as _d, timedelta as _td
    freq_map = {'daily':1,'weekly':7,'biweekly':14,'monthly':30,'bimonthly':60,'annual':365}
    step  = freq_map.get(recurr['frequency'], 30)
    start = _d.fromisoformat(recurr['next_date']) if recurr.get('next_date') else _d.today()
    # Remove previous future pending pre-transactions from this recurring
    conn.execute(
        "DELETE FROM pre_transactions WHERE recurring_id=? AND status='pending' AND date >= date('now')",
        (recurr_id,)
    )
    cur = start
    for _ in range(3):  # generate next 3 occurrences
        if cur < _d.today():
            cur += _td(days=step)
            continue
        conn.execute(
            'INSERT INTO pre_transactions (date, description, category, amount, type, account_id, entity_id, notes, status, recurring_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (cur.isoformat(), recurr['name'], recurr.get('category'), recurr['amount'],
             recurr.get('type','expense'), recurr.get('account_id'), recurr.get('entity_id'),
             f"Recorrente: {recurr['name']}", 'pending', recurr_id)
        )
        cur += _td(days=step)

@app.route('/api/recurring', methods=['POST'])
def create_recurring():
    d = request.json
    conn = get_db_connection()
    cur = conn.execute(
        'INSERT INTO recurring_expenses (name, category, amount, type, frequency, account_id, entity_id, next_date, active, notes) VALUES (?,?,?,?,?,?,?,?,?,?)',
        (d['name'], d.get('category'), d['amount'], d.get('type','expense'), d.get('frequency','monthly'),
         d.get('account_id') or None, d.get('entity_id') or None, d.get('next_date'), d.get('active', 1), d.get('notes'))
    )
    recurr_id = cur.lastrowid
    if d.get('active', 1) and d.get('next_date'):
        recurr_row = conn.execute('SELECT * FROM recurring_expenses WHERE id=?', (recurr_id,)).fetchone()
        _generate_pretxns_for_recurring(conn, recurr_id, dict(recurr_row))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'id': recurr_id}), 201

@app.route('/api/recurring/<int:id>', methods=['PUT'])
def update_recurring(id):
    d = request.json
    conn = get_db_connection()
    conn.execute(
        'UPDATE recurring_expenses SET name=?, category=?, amount=?, type=?, frequency=?, account_id=?, entity_id=?, next_date=?, active=?, notes=? WHERE id=?',
        (d['name'], d.get('category'), d['amount'], d.get('type','expense'), d.get('frequency','monthly'),
         d.get('account_id') or None, d.get('entity_id') or None, d.get('next_date'), d.get('active', 1), d.get('notes'), id)
    )
    if d.get('active', 1) and d.get('next_date'):
        _generate_pretxns_for_recurring(conn, id, d)
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/recurring/<int:id>', methods=['DELETE'])
def delete_recurring(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM recurring_expenses WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/recurring/<int:id>/pre-transactions', methods=['GET'])
def recurring_pre_transactions(id):
    """List pre-transactions linked to a specific recurring expense."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT pt.*, t.description as txn_description, t.date as txn_date
        FROM pre_transactions pt
        LEFT JOIN transactions t ON t.id = pt.transaction_id
        WHERE pt.recurring_id=?
        ORDER BY pt.date
    ''', (id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ─── PATRIMONY ────────────────────────────────────────────────────────────────

@app.route('/api/patrimony', methods=['GET'])
def get_patrimony():
    conn = get_db_connection()
    # Add columns if they don't exist yet (safe migration)
    for col, typedef in [('purchase_price', 'INTEGER DEFAULT 0'),
                         ('depreciation_rate', 'REAL DEFAULT 0')]:
        try:
            conn.execute(f'ALTER TABLE patrimony_items ADD COLUMN {col} {typedef}')
            conn.commit()
        except Exception:
            pass

    rows = conn.execute('SELECT * FROM patrimony_items ORDER BY type, value DESC').fetchall()
    conn.close()

    result = []
    for r in rows:
        item = dict(r)
        purchase = item.get('purchase_price') or 0
        rate     = item.get('depreciation_rate') or 0   # % ao ano
        acq_date = item.get('acquisition_date')

        # Years since acquisition (for straight-line depreciation display)
        years = 0.0
        if acq_date:
            try:
                from datetime import date
                acq = date.fromisoformat(acq_date)
                years = max(0, (date.today() - acq).days / 365.25)
            except Exception:
                pass

        # Straight-line value change from purchase price:
        #   rate > 0  →  appreciation (valorização)
        #   rate < 0  →  depreciation (desvalorização)
        if purchase:
            change_amount = round(purchase * (rate / 100) * years) if rate else 0
            real_value    = max(0, purchase + change_amount)
        else:
            # No purchase price → real value = stated current value (no adjustment)
            change_amount = 0
            real_value    = item['value']

        item['purchase_price']   = purchase
        item['depreciation_rate']= rate
        item['change_amount']    = change_amount   # + valorização / - depreciação
        item['real_value']       = real_value
        item['years_owned']      = round(years, 1)
        item['is_appreciating']  = rate > 0        # True = valorização
        result.append(item)


    return jsonify(result)


@app.route('/api/patrimony', methods=['POST'])
def create_patrimony():
    d = request.json
    conn = get_db_connection()
    for col, typedef in [('purchase_price', 'INTEGER DEFAULT 0'),
                         ('depreciation_rate', 'REAL DEFAULT 0')]:
        try:
            conn.execute(f'ALTER TABLE patrimony_items ADD COLUMN {col} {typedef}')
            conn.commit()
        except Exception:
            pass
    conn.execute(
        'INSERT INTO patrimony_items (name, type, category, value, purchase_price, depreciation_rate, acquisition_date, notes) VALUES (?,?,?,?,?,?,?,?)',
        (d['name'], d.get('type','asset'), d.get('category'), int(round(float(d.get('value', 0)))),
         int(round(float(d.get('purchase_price') or 0))),
         float(d.get('depreciation_rate') or 0),
         d.get('acquisition_date'), d.get('notes'))
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 201

@app.route('/api/patrimony/<int:id>', methods=['PUT'])
def update_patrimony(id):
    d = request.json
    conn = get_db_connection()
    conn.execute(
        'UPDATE patrimony_items SET name=?, type=?, category=?, value=?, purchase_price=?, depreciation_rate=?, acquisition_date=?, notes=? WHERE id=?',
        (d['name'], d.get('type','asset'), d.get('category'),
         int(round(float(d.get('value', 0)))),
         int(round(float(d.get('purchase_price') or 0))),
         float(d.get('depreciation_rate') or 0),
         d.get('acquisition_date'), d.get('notes'), id)
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/patrimony/<int:id>', methods=['DELETE'])
def delete_patrimony(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM patrimony_items WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})



# ─── CASH FLOW FORECAST ────────────────────────────────────────────────────────

from datetime import date as _date, timedelta as _timedelta

@app.route('/api/forecast', methods=['GET'])
def get_forecast():
    """Generate N-day cash flow forecast based on recurring expenses."""
    days = min(max(int(request.args.get('days', 90)), 7), 365)
    conn = get_db_connection()
    recurrents = conn.execute(
        "SELECT * FROM recurring_expenses WHERE active=1"
    ).fetchall()
    acc_balance = conn.execute(
        'SELECT COALESCE(SUM(balance),0) as total FROM accounts'
    ).fetchone()['total']

    # Actual cashflow for the same forward period (historical last N days for reference)
    actual_rows = conn.execute(f'''
        SELECT strftime('%Y-%m', date) as month,
               SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as actual_income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as actual_expense
        FROM transactions
        WHERE date >= date('now', '-{days} days') AND date <= date('now')
        GROUP BY month ORDER BY month
    ''').fetchall()

    # Average monthly income — last 3 months
    avg_inc = conn.execute('''
        SELECT AVG(monthly_inc) as avg FROM (
            SELECT strftime('%Y-%m', date) as m, SUM(amount) as monthly_inc
            FROM transactions WHERE type='income' AND date >= date('now','-3 months')
            GROUP BY m
        )
    ''').fetchone()['avg'] or 0

    conn.close()

    today = _date.today()
    horizon = today + _timedelta(days=days)

    events = []
    freq_map = {'daily': 1, 'weekly': 7, 'biweekly': 14, 'monthly': 30, 'bimonthly': 60, 'annual': 365}
    for r in recurrents:
        start = _date.fromisoformat(r['next_date']) if r['next_date'] else today
        step  = freq_map.get(r['frequency'], 30)
        cur   = start
        while cur <= horizon:
            if cur >= today:
                events.append({
                    'date': cur.isoformat(),
                    'name': r['name'],
                    'amount': r['amount'],
                    'type': r['type'],
                    'category': r['category'],
                    'recurring_id': r['id'],
                })
            cur += _timedelta(days=step)

    months = {}
    running = acc_balance
    for e in sorted(events, key=lambda x: x['date']):
        m = e['date'][:7]
        if m not in months:
            months[m] = {'month': m, 'inflow': 0, 'outflow': 0, 'balance': 0, 'net': 0}
        if e['type'] == 'income':
            months[m]['inflow'] += e['amount']
            running += e['amount']
        else:
            months[m]['outflow'] += e['amount']
            running -= e['amount']
        months[m]['balance'] = round(running, 2)
        months[m]['net'] = round(months[m]['inflow'] - months[m]['outflow'], 2)

    total_inflow  = sum(e['amount'] for e in events if e['type'] == 'income')
    total_outflow = sum(e['amount'] for e in events if e['type'] != 'income')

    return jsonify({
        'events':           sorted(events, key=lambda x: x['date']),
        'monthly':          list(months.values()),
        'actual_cashflow':  [dict(r) for r in actual_rows],
        'current_balance':  acc_balance,
        'avg_monthly_income': round(avg_inc, 2),
        'total_inflow':     round(total_inflow, 2),
        'total_outflow':    round(total_outflow, 2),
        'days':             days,
    })



# ─── PRE-TRANSACTIONS ─────────────────────────────────────────────────────────

@app.route('/api/pre-transactions', methods=['GET'])
def get_pre_transactions():
    conn = get_db_connection()
    # Ensure new columns exist (safe migration)
    for col, ctype in [('recurring_id','INTEGER'), ('transaction_id','INTEGER')]:
        try:
            conn.execute(f'ALTER TABLE pre_transactions ADD COLUMN {col} {ctype}')
            conn.commit()
        except Exception:
            pass
    rows = conn.execute('''
        SELECT pt.*,
               a.name as account_name, 
               COALESCE(NULLIF(e.display_name, ''), e.name) as entity_name,
               r.name as recurring_name,
               t.description as linked_txn_description
        FROM pre_transactions pt
        LEFT JOIN accounts a           ON pt.account_id=a.id
        LEFT JOIN entities e           ON pt.entity_id=e.id
        LEFT JOIN recurring_expenses r ON pt.recurring_id=r.id
        LEFT JOIN transactions t       ON pt.transaction_id=t.id
        ORDER BY pt.date
    ''').fetchall()
    rules, enabled = _get_redaction_context(conn)
    conn.close()
    
    result = []
    for r in rows:
        d = dict(r)
        d['description'] = _redact(d['description'], rules, enabled)
        d['notes'] = _redact(d['notes'], rules, enabled)
        d['entity_name'] = _redact(d['entity_name'], rules, enabled)
        result.append(d)
    return jsonify(result)

@app.route('/api/pre-transactions', methods=['POST'])
def create_pre_transaction():
    d = request.json
    conn = get_db_connection()
    amount = int(round(float(d.get('amount', 0))))
    conn.execute(
        'INSERT INTO pre_transactions (date, description, category, amount, type, account_id, entity_id, notes, status, recurring_id, transaction_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
        (d['date'], d['description'], d.get('category'), amount, d.get('type','expense'),
         d.get('account_id') or None, d.get('entity_id') or None, d.get('notes'),
         d.get('status','pending'), d.get('recurring_id') or None, d.get('transaction_id') or None)
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'}), 201

@app.route('/api/pre-transactions/<int:id>', methods=['PUT'])
def update_pre_transaction(id):
    d = request.json
    conn = get_db_connection()
    transaction_id = d.get('transaction_id') or None
    amount = int(round(float(d.get('amount', 0))))
    # If transaction_id is being set, auto-confirm
    new_status = d.get('status', 'pending')
    if transaction_id:
        new_status = 'confirmed'
    conn.execute(
        'UPDATE pre_transactions SET date=?, description=?, category=?, amount=?, type=?, account_id=?, entity_id=?, notes=?, status=?, transaction_id=? WHERE id=?',
        (d['date'], d['description'], d.get('category'), amount, d.get('type','expense'),
         d.get('account_id') or None, d.get('entity_id') or None, d.get('notes'),
         new_status, transaction_id, id)
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/pre-transactions/<int:id>', methods=['DELETE'])
def delete_pre_transaction(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM pre_transactions WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/pre-transactions/<int:id>/confirm', methods=['POST'])
def confirm_pre_transaction(id):
    """Convert a pre-transaction into a real transaction, or link an existing one."""
    d = request.json or {}
    existing_txn_id = d.get('transaction_id')  # link existing transaction instead of creating new
    conn = get_db_connection()
    pt = conn.execute('SELECT * FROM pre_transactions WHERE id=?', (id,)).fetchone()
    if not pt:
        conn.close()
        return jsonify({'error': 'Not found'}), 404

    if existing_txn_id:
        # Just link the existing transaction and mark confirmed
        conn.execute(
            "UPDATE pre_transactions SET status='confirmed', transaction_id=? WHERE id=?",
            (existing_txn_id, id)
        )
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'transaction_id': existing_txn_id})

    # Create a new real transaction from this pre-transaction
    cur = conn.execute(
        'INSERT INTO transactions (account_id, date, description, category, amount, type, is_manual, notes, recurring_id) VALUES (?,?,?,?,?,?,1,?,?)',
        (pt['account_id'], pt['date'], pt['description'], pt['category'], pt['amount'], pt['type'], pt['notes'], pt['recurring_id'])
    )
    txn_id = cur.lastrowid
    if pt['account_id']:
        if pt['type'] == 'expense':
            conn.execute('UPDATE accounts SET balance=balance-? WHERE id=?', (pt['amount'], pt['account_id']))
        else:
            conn.execute('UPDATE accounts SET balance=balance+? WHERE id=?', (pt['amount'], pt['account_id']))
    conn.execute(
        "UPDATE pre_transactions SET status='confirmed', transaction_id=? WHERE id=?",
        (txn_id, id)
    )
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'transaction_id': txn_id})


@app.route('/api/config', methods=['GET'])
def get_config():
    conn = get_db_connection()
    rows = conn.execute('SELECT key, value FROM system_config').fetchall()
    conn.close()
    return jsonify({r['key']: r['value'] for r in rows})

@app.route('/api/config', methods=['POST'])
def update_config():
    d = request.json
    conn = get_db_connection()
    for k, v in d.items():
        conn.execute('INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?,?, datetime("now"))', (k, str(v)))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

@app.route('/api/redacted-texts', methods=['GET'])
def get_redacted_texts():
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM redacted_texts ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/redacted-texts', methods=['POST'])
def add_redacted_text():
    d = request.json
    conn = get_db_connection()
    conn.execute('INSERT OR IGNORE INTO redacted_texts (text) VALUES (?)', (d['text'],))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

@app.route('/api/redacted-texts/<int:id>', methods=['DELETE'])
def delete_redacted_text(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM redacted_texts WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status':'success'})

@app.route('/api/redacted-texts/auto-discover', methods=['POST'])
def auto_discover_redacted():
    conn = get_db_connection()
    # Key patterns from common banks (Nubank, Inter, etc.)
    prefixes = [
        "Pix Enviado - ", "Pix Recebido - ", 
        "Transferência recebida - ", "Transferencia Enviada - ",
        "Transferência enviada - ", "Transferência Recebida - ",
        "PIX - RECEBIDO - ", "PIX - ENVIADO - ",
        "TED - ENVIADA - ", "TED - RECEBIDA - ",
        "DOC - ENVIADA - ", "DOC - RECEBIDA - ",
        "PGTO - PIX - ", "DEPOSITO PIX - "
    ]
    
    added_count = 0
    for p in prefixes:
        # We look for descriptions starting with these patterns
        rows = conn.execute("SELECT description FROM transactions WHERE description LIKE ?", (p + '%',)).fetchall()
        for r in rows:
            extracted = r['description'][len(p):].strip()
            # We only add if it's a substantive string
            if extracted and len(extracted) >= 3:
                cur = conn.execute('INSERT OR IGNORE INTO redacted_texts (text) VALUES (?)', (extracted,))
                if cur.rowcount > 0:
                    added_count += 1
    
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'added_count': added_count})

@app.route('/api/redacted-texts/permanently-redact', methods=['POST'])
def permanently_redact():
    conn = get_db_connection()
    # 1. Backfill raw_description if NULL (safeguard)
    conn.execute('UPDATE transactions SET raw_description = description WHERE raw_description IS NULL')
    
    # 2. Get redaction rules
    rules_rows = conn.execute('SELECT text FROM redacted_texts').fetchall()
    rules = [r['text'] for r in rules_rows if r['text']]
    
    if not rules:
        conn.close()
        return jsonify({'status': 'success', 'updated_count': 0, 'message': 'Nenhuma regra de redação cadastrada.'})
    
    # 3. Apply redaction to all transactions
    txns = conn.execute('SELECT id, raw_description, description FROM transactions').fetchall()
    
    updated_count = 0
    for t in txns:
        original = t['raw_description']
        if not original: continue
        
        redacted = original
        for rule in rules:
            redacted = redacted.replace(rule, '[redacted]')
            
        # Update if the new redacted version is different from the CURRENT description
        if redacted != t['description']:
            # flag 64 = description redatected            
            conn.execute('UPDATE transactions SET description = ?, flags = flags | 64 WHERE id = ?', (redacted, t['id']))
            updated_count += 1
            
    conn.commit()
    conn.close()
    return jsonify({
        'status': 'success', 
        'updated_count': updated_count,
        'message': f'{updated_count} transações foram atualizadas com sucesso.'
    })

@app.route('/api/reports/unified-flow', methods=['GET'])
def get_unified_flow():
    """Unified Flow: Past (-6m) and Future (+6m) cash flow including credits and pre-transactions."""
    conn = get_db_connection()
    today = datetime.now().strftime('%Y-%m-%d')
    start_date = (datetime.now() - timedelta(days=180)).strftime('%Y-%m-%d')
    end_date = (datetime.now() + timedelta(days=180)).strftime('%Y-%m-%d')

    # Current Balances Total
    current_balance = conn.execute('SELECT SUM(balance) FROM accounts').fetchone()[0] or 0
    
    # 1. Past Transactions (Real)
    # Note: Credit transactions impact at 'liquidation_date' if set, otherwise ignored in balance flow here
    past_txns = conn.execute('''
        SELECT date, type, amount, raw_amount 
        FROM transactions 
        WHERE date >= ? AND date <= ?
    ''', (start_date, today)).fetchall()

    # 2. Future Pre-Transactions (Pending)
    future_pre = conn.execute('''
        SELECT date, type, amount 
        FROM pre_transactions 
        WHERE date > ? AND date <= ? AND status = 'pending'
    ''', (today, end_date)).fetchall()

    # 3. Future Credit Liquidations
    future_credits = conn.execute('''
        SELECT liquidation_date as date, raw_amount as amount 
        FROM transactions 
        WHERE type = 'credit' AND liquidation_date > ? AND liquidation_date <= ?
    ''', (today, end_date)).fetchall()

    # Build a timeline map
    timeline = {}
    
    def add_val(d, t, val):
        if d not in timeline: 
            timeline[d] = {'income': 0, 'expense': 0, 'credit': 0, 'forecast': 0, 'transfer': 0}
        if t in timeline[d]:
            timeline[d][t] += val

    for t in past_txns:
        if t['type'] == 'credit':
            add_val(t['date'], 'credit', t['raw_amount'])
        else:
            add_val(t['date'], t['type'], t['amount'])

    for t in future_pre:
        add_val(t['date'], t['type'], t['amount'])

    for t in future_credits:
        # Credits in the future Liquidation phase are expenses for the pocket
        add_val(t['date'], 'expense', t['amount'])

    # Sort days
    sorted_days = sorted(timeline.keys())
    
    # We want to create the balance line.
    # Today's balance is current_balance.
    # For dates > today, it grows/shrinks.
    # For dates < today, we work backwards.
    
    # Simplified monthly view or daily? Let's do daily but aggregated for the chart.
    results = []
    
    # Since working backwards is tricky with many days, we find the cumulative sum since start till today first.
    # Actually, easier: today is anchor.
    # Let's calculate daily changes.
    
    # Forecast line
    running_balance = current_balance
    
    # Future
    full_timeline = []
    for day in sorted_days:
        d = timeline[day]
        item = {
            'date': day,
            'income': d['income'],
            'expense': d['expense'],
            'credit': d['credit'],
            'balance': 0 # placeholder
        }
        full_timeline.append(item)

    # To calculate historical balance, we find balance_at_start.
    # balance_at_today = balance_at_start + sum(changes from start to today).
    # so balance_at_start = balance_at_today - sum(changes from start to today).
    
    changes_till_today = 0
    for item in full_timeline:
        if item['date'] <= today:
            changes_till_today += (item['income'] - item['expense'])
            
    balance_at_start = current_balance - changes_till_today
    
    current_run = balance_at_start
    for item in full_timeline:
        current_run += (item['income'] - item['expense'])
        item['balance'] = round(current_run, 2)

    conn.close()
    return jsonify(full_timeline)

# ─── AUTOMATION RULES ────────────────────────────────────────────────────────

def _ensure_automation_tables(conn):
    """Create automation tables if they don't exist yet (idempotent)."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS automation_rules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            match_text   TEXT NOT NULL,
            match_type   TEXT NOT NULL DEFAULT 'contains',
            priority     INTEGER NOT NULL DEFAULT 100,
            active       INTEGER NOT NULL DEFAULT 1,
            trigger_mode TEXT NOT NULL DEFAULT 'all',
            apply_category  TEXT,
            apply_tags      TEXT,
            apply_entity_id INTEGER,
            apply_flags     INTEGER DEFAULT 0,
            apply_type      TEXT,
            apply_notes     TEXT,
            created_at   TEXT DEFAULT (datetime('now')),
            updated_at   TEXT DEFAULT (datetime('now'))
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS automation_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id  INTEGER NOT NULL,
            rule_id         INTEGER NOT NULL,
            applied_at      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
            FOREIGN KEY (rule_id)        REFERENCES automation_rules(id) ON DELETE CASCADE
        )
    ''')
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_autolog_txn ON automation_logs(transaction_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_autolog_rule ON automation_logs(rule_id)")
    except Exception:
        pass
    # Safe column migrations for older DBs
    for col, coltype in [
        ('apply_account_ids',            'TEXT'),
        ('apply_source_account_id',      'INTEGER'),
        ('apply_destination_account_id', 'INTEGER'),
    ]:
        try:
            conn.execute(f"ALTER TABLE automation_rules ADD COLUMN {col} {coltype}")
        except Exception:
            pass


def _matches_rule(description, rule):
    """Check if description matches a rule's match_type/match_text."""
    desc = (description or '').lower()
    text = (rule['match_text'] or '').lower()
    mt = rule['match_type']
    if mt == 'exact':
        return desc == text
    elif mt == 'starts_with':
        return desc.startswith(text)
    elif mt == 'ends_with':
        return desc.endswith(text)
    elif mt == 'regex':
        import re
        try:
            return bool(re.search(rule['match_text'], description or '', re.IGNORECASE))
        except Exception:
            return False
    else:  # contains (default)
        return text in desc


def _apply_rule_to_transactions(conn, rule, txn_rows):
    """Apply a single rule to a list of transaction dicts. Returns count updated."""
    updated = 0
    rule_id = rule['id']
    tag_names = [t.strip() for t in (rule['apply_tags'] or '').split(',') if t.strip()]

    # Build account filter set (if restricted to specific accounts)
    account_ids_str = rule.get('apply_account_ids') or ''
    allowed_account_ids = set(int(x) for x in account_ids_str.split(',') if x.strip().isdigit())

    for txn in txn_rows:
        if not _matches_rule(txn['description'], rule):
            continue

        # Skip if rule is scoped to specific accounts and this txn's account doesn't match
        if allowed_account_ids and txn.get('account_id') not in allowed_account_ids:
            continue

        # Build update fields dynamically (only set non-empty ones)
        updates = []
        params = []
        if rule['apply_category']:
            updates.append('category=?')
            params.append(rule['apply_category'])
        if rule['apply_type']:
            updates.append('type=?')
            params.append(rule['apply_type'])
        if rule['apply_entity_id']:
            updates.append('entity_id=?')
            params.append(rule['apply_entity_id'])
        if rule['apply_flags']:
            updates.append('flags = flags | ?')
            params.append(rule['apply_flags'])
        if rule['apply_notes']:
            updates.append('notes=?')
            params.append(rule['apply_notes'])
        if rule.get('apply_source_account_id'):
            updates.append('account_id=?')
            params.append(rule['apply_source_account_id'])
        if rule.get('apply_destination_account_id'):
            updates.append('destination_account_id=?')
            params.append(rule['apply_destination_account_id'])

        if updates:
            params.append(txn['id'])
            conn.execute(f"UPDATE transactions SET {', '.join(updates)} WHERE id=?", params)

        # Tags
        if tag_names:
            _sync_tags_append(conn, txn['id'], tag_names)

        # Log
        conn.execute(
            'INSERT OR IGNORE INTO automation_logs (transaction_id, rule_id) VALUES (?,?)',
            (txn['id'], rule_id)
        )
        updated += 1

    return updated


def _sync_tags_append(conn, txn_id, tag_names):
    """Add tags to a transaction without removing existing ones."""
    for name in tag_names:
        name = name.strip().lower()
        if not name:
            continue
        conn.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (name,))
        tag_id = conn.execute('SELECT id FROM tags WHERE name=?', (name,)).fetchone()['id']
        conn.execute(
            'INSERT OR IGNORE INTO transaction_tags (transaction_id, tag_id) VALUES (?,?)',
            (txn_id, tag_id)
        )


@app.route('/api/automation/rules', methods=['GET'])
def get_automation_rules():
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    rows = conn.execute('''
        SELECT r.*,
               COUNT(DISTINCT al.transaction_id) as affected_count
        FROM automation_rules r
        LEFT JOIN automation_logs al ON al.rule_id = r.id
        GROUP BY r.id
        ORDER BY r.priority, r.id
    ''').fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d['apply_tags_list'] = [t.strip() for t in (d.get('apply_tags') or '').split(',') if t.strip()]
        result.append(d)
    return jsonify(result)


@app.route('/api/automation/rules', methods=['POST'])
def create_automation_rule():
    data = request.json
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    tags_str = ','.join(data.get('apply_tags', [])) if isinstance(data.get('apply_tags'), list) else (data.get('apply_tags') or '')
    acc_ids = data.get('apply_account_ids', [])
    acc_ids_str = ','.join(str(x) for x in acc_ids) if isinstance(acc_ids, list) else (acc_ids or '')
    cur = conn.execute('''
        INSERT INTO automation_rules
            (name, match_text, match_type, priority, active, trigger_mode,
             apply_category, apply_tags, apply_entity_id, apply_flags, apply_type, apply_notes,
             apply_account_ids, apply_source_account_id, apply_destination_account_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        data['name'], data['match_text'], data.get('match_type', 'contains'),
        int(data.get('priority', 100)), int(data.get('active', 1)), data.get('trigger_mode', 'all'),
        data.get('apply_category'), tags_str,
        data.get('apply_entity_id') or None, int(data.get('apply_flags', 0)),
        data.get('apply_type'), data.get('apply_notes'),
        acc_ids_str or None,
        data.get('apply_source_account_id') or None,
        data.get('apply_destination_account_id') or None,
    ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'id': cur.lastrowid}), 201


@app.route('/api/automation/rules/<int:id>', methods=['PUT'])
def update_automation_rule(id):
    data = request.json
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    tags_str = ','.join(data.get('apply_tags', [])) if isinstance(data.get('apply_tags'), list) else (data.get('apply_tags') or '')
    acc_ids = data.get('apply_account_ids', [])
    acc_ids_str = ','.join(str(x) for x in acc_ids) if isinstance(acc_ids, list) else (acc_ids or '')
    conn.execute('''
        UPDATE automation_rules SET
            name=?, match_text=?, match_type=?, priority=?, active=?, trigger_mode=?,
            apply_category=?, apply_tags=?, apply_entity_id=?, apply_flags=?, apply_type=?, apply_notes=?,
            apply_account_ids=?, apply_source_account_id=?, apply_destination_account_id=?,
            updated_at=datetime('now')
        WHERE id=?
    ''', (
        data['name'], data['match_text'], data.get('match_type', 'contains'),
        int(data.get('priority', 100)), int(data.get('active', 1)), data.get('trigger_mode', 'all'),
        data.get('apply_category'), tags_str,
        data.get('apply_entity_id') or None, int(data.get('apply_flags', 0)),
        data.get('apply_type'), data.get('apply_notes'),
        acc_ids_str or None,
        data.get('apply_source_account_id') or None,
        data.get('apply_destination_account_id') or None,
        id
    ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


@app.route('/api/automation/rules/<int:id>', methods=['DELETE'])
def delete_automation_rule(id):
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    conn.execute('DELETE FROM automation_logs WHERE rule_id=?', (id,))
    conn.execute('DELETE FROM automation_rules WHERE id=?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


@app.route('/api/automation/rules/<int:id>/dryrun', methods=['GET'])
def dryrun_automation_rule(id):
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    rule = conn.execute('SELECT * FROM automation_rules WHERE id=?', (id,)).fetchone()
    if not rule:
        conn.close()
        return jsonify({'error': 'Rule not found'}), 404

    txns = conn.execute('SELECT id, description, date, amount, type, category FROM transactions ORDER BY date DESC').fetchall()
    rule = dict(rule)
    matched = [dict(t) for t in txns if _matches_rule(t['description'], rule)]
    conn.close()
    return jsonify({
        'affected': len(matched),
        'transactions': matched[:50]  # return first 50 for preview
    })


@app.route('/api/automation/rules/<int:id>/apply', methods=['POST'])
def apply_automation_rule(id):
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    rule = conn.execute('SELECT * FROM automation_rules WHERE id=?', (id,)).fetchone()
    if not rule:
        conn.close()
        return jsonify({'error': 'Rule not found'}), 404

    txns = conn.execute('SELECT * FROM transactions').fetchall()
    rule = dict(rule)
    updated = _apply_rule_to_transactions(conn, rule, [dict(t) for t in txns])
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'updated': updated})


@app.route('/api/automation/apply-all', methods=['POST'])
def apply_all_automation_rules():
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    rules = conn.execute('SELECT * FROM automation_rules WHERE active=1 ORDER BY priority').fetchall()
    txns = conn.execute('SELECT * FROM transactions').fetchall()
    txn_dicts = [dict(t) for t in txns]

    total_updated = 0
    for rule in rules:
        rule_d = dict(rule)
        updated = _apply_rule_to_transactions(conn, rule_d, txn_dicts)
        total_updated += updated

    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'updated': total_updated})


@app.route('/api/automation/patterns', methods=['GET'])
def get_automation_patterns():
    """Return grouped descriptions with counts and sample transactions."""
    conn = get_db_connection()
    _ensure_automation_tables(conn)

    # Group by description with count
    rows = conn.execute('''
        SELECT description,
               COUNT(*) as count
        FROM transactions
        WHERE description IS NOT NULL AND description != ''
        GROUP BY description
        HAVING count > 1 ORDER BY count DESC
    ''').fetchall()

    # For each pattern, get up to 3 sample transactions
    result = []
    for row in rows:
        desc = row['description']
        samples = conn.execute('''
            SELECT transactions.id, transactions.date, transactions.amount, transactions.type, transactions.category, accounts.name as account_name, raw_amount
            FROM transactions join accounts on accounts.id = transactions.account_id
            WHERE transactions.description = ?
            ORDER BY transactions.date DESC
            LIMIT 3
        ''', (desc,)).fetchall()
        result.append({
            'description': desc,
            'count': row['count'],
            'samples': [dict(s) for s in samples]
        })

    conn.close()
    return jsonify(result)


@app.route('/api/automation/logs', methods=['GET'])
def get_automation_logs():
    """Return logs of which rules were applied to which transactions."""
    conn = get_db_connection()
    _ensure_automation_tables(conn)
    rule_id = request.args.get('rule_id')
    txn_id = request.args.get('transaction_id')

    query = '''
        SELECT al.*, r.name as rule_name, t.description as txn_description, t.date as txn_date
        FROM automation_logs al
        JOIN automation_rules r ON r.id = al.rule_id
        JOIN transactions t ON t.id = al.transaction_id
        WHERE 1=1
    '''
    params = []
    if rule_id:
        query += ' AND al.rule_id=?'
        params.append(int(rule_id))
    if txn_id:
        query += ' AND al.transaction_id=?'
        params.append(int(txn_id))
    query += ' ORDER BY al.applied_at DESC LIMIT 200'

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
