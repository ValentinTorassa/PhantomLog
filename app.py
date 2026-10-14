# app.py
from flask import Flask, request, render_template, redirect, url_for, Response
from functools import wraps
from datetime import datetime, timezone
import csv
import hmac
import ipaddress
import math
import os
import threading
import time
import uuid

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

app = Flask(__name__)


def env_int(name, default):
    value = os.environ.get(name, '').strip()
    return int(value) if value else default


# Detras de un proxy (Render, Railway, nginx), request.remote_addr es la IP
# del proxy, no la de quien hizo clic. ProxyFix toma la IP de X-Forwarded-For,
# pero ese header lo puede escribir cualquiera: solo hay que confiar en tantos
# saltos como proxies reales haya delante de la app. Con 0 (por defecto) el
# header se ignora.
TRUSTED_PROXIES = env_int('TRUSTED_PROXIES', 0)
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES)

# Directorio de datos configurable (DATA_DIR); por defecto, junto a app.py.
DATA_DIR = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(DATA_DIR, 'logs.csv')
LINKS_FILE = os.path.join(DATA_DIR, 'links.csv')

# Tope de longitud para los campos que entran por request (input sin limite).
MAX_FIELD_LEN = 512

# Topes de /log por ventana fija (0 desactiva uno). Por cliente cuenta cada
# pedido, valido o no; por link, solo los clics que se registran. Con ids
# validados contra links.csv, logs.csv crece como mucho RATE_LIMIT_PER_LINK
# filas por link y por ventana. Los contadores viven en memoria de cada
# proceso: con varios workers de gunicorn, cada uno cuenta por su lado.
RATE_LIMIT_WINDOW = env_int('RATE_LIMIT_WINDOW_SECONDS', 3600)
RATE_LIMIT_PER_CLIENT = env_int('RATE_LIMIT_PER_CLIENT', 120)
RATE_LIMIT_PER_LINK = env_int('RATE_LIMIT_PER_LINK', 10)


# Crear archivos si no existen (tambien al correr bajo gunicorn).
def init_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'id', 'ip', 'user_agent', 'method'])

    if not os.path.exists(LINKS_FILE):
        with open(LINKS_FILE, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['unique_id', 'user_id'])


def csv_safe(value):
    # Neutraliza la inyeccion de formulas al abrir el CSV en una planilla y
    # recorta el valor para evitar input sin limite.
    text = '' if value is None else str(value)
    text = text.replace('\r', ' ').replace('\n', ' ')[:MAX_FIELD_LEN]
    if text and text[0] in ('=', '+', '-', '@', '\t'):
        text = "'" + text
    return text


class RateLimiter:
    """Ventana fija por clave, en memoria y con cantidad de claves acotada."""

    MAX_KEYS = 10000

    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self._hits = {}  # clave -> (inicio de la ventana, pedidos)
        self._lock = threading.Lock()

    def hit(self, key, now=None):
        """Cuenta un pedido. Devuelve 0 si entra, o los segundos que faltan
        para que la clave vuelva a tener cupo."""
        if self.limit <= 0:
            return 0
        now = time.monotonic() if now is None else now
        with self._lock:
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            if count >= self.limit:
                return max(1, math.ceil(self.window - (now - start)))
            if key not in self._hits and len(self._hits) >= self.MAX_KEYS:
                self._hits = {k: v for k, v in self._hits.items()
                              if now - v[0] < self.window}
                if len(self._hits) >= self.MAX_KEYS:
                    # Tabla llena con ventanas vigentes (muchas IPs a la
                    # vez): se rechaza en vez de olvidar los topes.
                    return self.window
            self._hits[key] = (start, count + 1)
            return 0


client_limiter = RateLimiter(RATE_LIMIT_PER_CLIENT, RATE_LIMIT_WINDOW)
link_limiter = RateLimiter(RATE_LIMIT_PER_LINK, RATE_LIMIT_WINDOW)


def client_key(addr):
    # Un /64 de IPv6 suele ser de un solo cliente: cambiar de direccion
    # dentro de el no da cupo nuevo.
    try:
        ip = ipaddress.ip_address(addr or '')
    except ValueError:
        return addr or ''
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f'{ip}/64', strict=False))
    return str(ip)


_links_cache = {'stamp': None, 'ids': frozenset()}


def known_link_ids():
    # Relee links.csv solo cuando cambio (otro worker pudo agregar links).
    try:
        st = os.stat(LINKS_FILE)
    except FileNotFoundError:
        return frozenset()
    stamp = (st.st_mtime_ns, st.st_size)
    if _links_cache['stamp'] != stamp:
        with open(LINKS_FILE, newline='') as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            ids = frozenset(row[0] for row in reader if row)
        _links_cache.update(stamp=stamp, ids=ids)
    return _links_cache['ids']


def too_many_requests(retry_after):
    return Response('', 429, {'Retry-After': str(retry_after)})


# --- Autenticacion del panel (HTTP Basic sobre HTTPS) ---
# Credenciales por variables de entorno. Sin ADMIN_PASSWORD_HASH el panel se
# bloquea (fail-closed); nunca hay contrasena por defecto. El endpoint publico
# /log sigue andando aunque el panel no este configurado.
def _admin_user():
    return os.environ.get('ADMIN_USER', 'admin')


def _admin_password_hash():
    return os.environ.get('ADMIN_PASSWORD_HASH')


def _auth_ok(auth):
    pw_hash = _admin_password_hash()
    if not pw_hash or auth is None:
        return False
    user_ok = hmac.compare_digest(auth.username or '', _admin_user())
    pass_ok = check_password_hash(pw_hash, auth.password or '')
    return user_ok and pass_ok


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _admin_password_hash():
            return 'Admin credentials not configured (set ADMIN_PASSWORD_HASH)', 503
        if not _auth_ok(request.authorization):
            return Response(
                'Authentication required', 401,
                {'WWW-Authenticate': 'Basic realm="PhantomLog"'},
            )
        return view(*args, **kwargs)

    return wrapped


@app.route('/')
@require_auth
def index():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, newline='') as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            logs = [row for row in reader if row]

    links = []
    if os.path.exists(LINKS_FILE):
        with open(LINKS_FILE, newline='') as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            links = [(row[1], request.url_root + 'log?id=' + row[0])
                     for row in reader if len(row) >= 2]

    return render_template('index.html', logs=logs, links=links)


@app.route('/generate', methods=['POST'])
@require_auth
def generate():
    user_id = (request.form.get('user_id') or '').strip()
    if not user_id:
        return 'Missing user_id parameter', 400

    unique_id = str(uuid.uuid4())
    with open(LINKS_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([unique_id, csv_safe(user_id)])

    return redirect(url_for('index'))


@app.route('/log')
def log_event():
    # Endpoint publico de rastreo: registra el clic. No redirige a ningun
    # destino controlado por el usuario (sin open redirect).
    ip = request.remote_addr
    retry = client_limiter.hit(client_key(ip))
    if retry:
        return too_many_requests(retry)

    # Solo cuentan los links generados desde el panel: un id inventado no
    # suma clics ni agrega filas al log.
    link_id = request.args.get('id', '')
    if link_id not in known_link_ids():
        return '', 404

    retry = link_limiter.hit(link_id)
    if retry:
        return too_many_requests(retry)

    user_agent = request.headers.get('User-Agent', '')
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    with open(LOG_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, csv_safe(link_id), csv_safe(ip),
                         csv_safe(user_agent), request.method])

    return '', 204  # No Content


# Crear los CSV al importar el modulo (p. ej. bajo gunicorn).
init_files()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
