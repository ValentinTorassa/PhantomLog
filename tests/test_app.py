import csv
import os

from conftest import ADMIN_USER, ADMIN_PASS, add_link, basic_auth

HEADER = ['timestamp', 'id', 'ip', 'user_agent', 'method']


def _read_csv(path):
    with open(path, newline='') as f:
        return list(csv.reader(f))


# --- Auth on the dashboard / admin routes ---

def test_dashboard_requires_auth(client):
    assert client.get('/').status_code == 401


def test_dashboard_allows_valid_credentials(client):
    r = client.get('/', headers=basic_auth(ADMIN_USER, ADMIN_PASS))
    assert r.status_code == 200


def test_dashboard_rejects_wrong_password(client):
    r = client.get('/', headers=basic_auth(ADMIN_USER, 'nope'))
    assert r.status_code == 401


def test_generate_requires_auth(client):
    assert client.post('/generate', data={'user_id': 'x'}).status_code == 401


def test_dashboard_denied_when_not_configured(unconfigured):
    assert unconfigured.app.test_client().get('/').status_code == 503


# --- Tracking endpoint is public ---

def test_log_works_without_auth(client, app_module):
    link_id = add_link(app_module)
    r = client.get('/log?id=' + link_id)
    assert r.status_code == 204
    rows = _read_csv(app_module.LOG_FILE)
    assert rows[0] == HEADER
    assert any(row[1] == link_id for row in rows[1:])


def test_log_public_even_when_not_configured(unconfigured):
    link_id = add_link(unconfigured)
    assert unconfigured.app.test_client().get('/log?id=' + link_id).status_code == 204


def test_log_accepts_link_made_by_generate(client, app_module):
    client.post('/generate', data={'user_id': 'persona-07'},
                headers=basic_auth(ADMIN_USER, ADMIN_PASS))
    link_id = _read_csv(app_module.LINKS_FILE)[-1][0]
    assert client.get('/log?id=' + link_id).status_code == 204
    assert _read_csv(app_module.LOG_FILE)[-1][1] == link_id


# --- Only known links are counted ---

def test_log_rejects_unknown_or_missing_id(client, app_module):
    add_link(app_module)
    assert client.get('/log?id=inventado').status_code == 404
    assert client.get('/log').status_code == 404
    assert _read_csv(app_module.LOG_FILE) == [HEADER]


# --- CSV files created on first run ---

def test_csv_files_created_on_import(app_module):
    assert os.path.exists(app_module.LOG_FILE)
    assert os.path.exists(app_module.LINKS_FILE)
    assert _read_csv(app_module.LOG_FILE)[0] == HEADER
    assert _read_csv(app_module.LINKS_FILE)[0] == ['unique_id', 'user_id']


# --- CSV / formula injection escaping ---

def test_log_escapes_formula_injection(client, app_module):
    # A formula as the id is not a known link, so it never reaches the CSV.
    assert client.get('/log?id==2+5').status_code == 404
    client.get('/log?id=' + add_link(app_module), headers={'User-Agent': '=cmd|calc'})
    last = _read_csv(app_module.LOG_FILE)[-1]
    assert last[3].startswith("'=")   # user-agent field


def test_generate_escapes_formula_injection(client, app_module):
    client.post('/generate', data={'user_id': '@SUM(1,2)'},
                headers=basic_auth(ADMIN_USER, ADMIN_PASS))
    last = _read_csv(app_module.LINKS_FILE)[-1]
    assert last[1].startswith("'@")


def test_long_input_is_truncated(client, app_module):
    client.get('/log?id=' + add_link(app_module), headers={'User-Agent': 'a' * 5000})
    last = _read_csv(app_module.LOG_FILE)[-1]
    assert len(last[3]) <= app_module.MAX_FIELD_LEN


# --- Method column, UTC timestamps and the proxy pitfall ---

def test_log_records_method_and_utc_timestamp(client, app_module):
    link_id = add_link(app_module)
    client.head('/log?id=' + link_id)
    last = _read_csv(app_module.LOG_FILE)[-1]
    assert last[1] == link_id
    assert last[4] == 'HEAD'
    assert last[0].endswith('Z') and 'T' in last[0]


def test_forwarded_for_ignored_without_trusted_proxies(client, app_module):
    client.get('/log?id=' + add_link(app_module),
               headers={'X-Forwarded-For': '203.0.113.9'},
               environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert _read_csv(app_module.LOG_FILE)[-1][2] == '127.0.0.1'


def test_proxyfix_trusts_only_the_last_hop(behind_one_proxy):
    client = behind_one_proxy.app.test_client()
    # El cliente invento el primer valor; el proxy agrego el segundo.
    client.get('/log?id=' + add_link(behind_one_proxy),
               headers={'X-Forwarded-For': '198.51.100.1, 203.0.113.9'},
               environ_base={'REMOTE_ADDR': '127.0.0.1'})
    assert _read_csv(behind_one_proxy.LOG_FILE)[-1][2] == '203.0.113.9'


# --- Rate limits on /log ---

def _from(ip):
    return {'environ_base': {'REMOTE_ADDR': ip}}


def test_link_limit_caps_clicks_per_link(load_app):
    module = load_app(RATE_LIMIT_PER_LINK='2')
    client = module.app.test_client()
    link_id = add_link(module)
    codes = [client.get('/log?id=' + link_id, **_from(f'198.51.100.{n}')).status_code
             for n in range(1, 5)]
    assert codes == [204, 204, 429, 429]
    assert len(_read_csv(module.LOG_FILE)) == 1 + 2
    r = client.get('/log?id=' + link_id, **_from('198.51.100.9'))
    assert 0 < int(r.headers['Retry-After']) <= module.RATE_LIMIT_WINDOW
    # Other links keep their own allowance.
    assert client.get('/log?id=' + add_link(module), **_from('198.51.100.9')).status_code == 204


def test_client_limit_counts_unknown_ids_too(load_app):
    module = load_app(RATE_LIMIT_PER_CLIENT='3')
    client = module.app.test_client()
    link_id = add_link(module)
    assert client.get('/log?id=adivinando-1', **_from('203.0.113.5')).status_code == 404
    assert client.get('/log?id=adivinando-2', **_from('203.0.113.5')).status_code == 404
    assert client.get('/log?id=' + link_id, **_from('203.0.113.5')).status_code == 204
    assert client.get('/log?id=' + link_id, **_from('203.0.113.5')).status_code == 429
    assert client.get('/log?id=' + link_id, **_from('203.0.113.6')).status_code == 204


def test_client_limit_groups_ipv6_by_64(load_app):
    module = load_app(RATE_LIMIT_PER_CLIENT='1')
    client = module.app.test_client()
    link_id = add_link(module)
    assert client.get('/log?id=' + link_id, **_from('2001:db8:1:2::1')).status_code == 204
    assert client.get('/log?id=' + link_id, **_from('2001:db8:1:2::ffff')).status_code == 429
    assert client.get('/log?id=' + link_id, **_from('2001:db8:1:3::1')).status_code == 204


def test_zero_disables_a_limit(load_app):
    module = load_app(RATE_LIMIT_PER_LINK='0', RATE_LIMIT_PER_CLIENT='0')
    client = module.app.test_client()
    link_id = add_link(module)
    assert all(client.get('/log?id=' + link_id).status_code == 204 for _ in range(30))


def test_window_resets_and_key_table_stays_bounded(app_module):
    limiter = app_module.RateLimiter(limit=1, window=60)
    assert limiter.hit('a', now=0) == 0
    assert limiter.hit('a', now=10) == 50
    assert limiter.hit('a', now=60) == 0
    limiter.MAX_KEYS = 2
    assert limiter.hit('b', now=60) == 0
    # Full of live windows: a new key is refused rather than unlimited.
    assert limiter.hit('c', now=61) == 60
    # Once the old windows expire, they are dropped to make room.
    assert limiter.hit('c', now=200) == 0
