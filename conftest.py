import base64
import csv
import importlib
import os
import sys
import uuid

import pytest
from werkzeug.security import generate_password_hash

ADMIN_USER = 'tester'
ADMIN_PASS = 's3cret-pass'


def basic_auth(user, pw):
    token = base64.b64encode(f'{user}:{pw}'.encode()).decode()
    return {'Authorization': 'Basic ' + token}


RATE_LIMIT_VARS = ('RATE_LIMIT_WINDOW_SECONDS', 'RATE_LIMIT_PER_CLIENT',
                   'RATE_LIMIT_PER_LINK')


def add_link(module, user_id='persona-01'):
    # Escribe un link como lo haria /generate, sin pasar por el panel.
    link_id = str(uuid.uuid4())
    with open(module.LINKS_FILE, mode='a', newline='') as f:
        csv.writer(f).writerow([link_id, user_id])
    return link_id


def _load_app(tmp_path, configured, trusted_proxies=0, env=None):
    os.environ['DATA_DIR'] = str(tmp_path)
    os.environ['ADMIN_USER'] = ADMIN_USER
    os.environ['TRUSTED_PROXIES'] = str(trusted_proxies)
    for name in RATE_LIMIT_VARS:
        os.environ.pop(name, None)
    os.environ.update(env or {})
    if configured:
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash(ADMIN_PASS)
    else:
        os.environ.pop('ADMIN_PASSWORD_HASH', None)
    sys.modules.pop('app', None)
    module = importlib.import_module('app')
    module.app.config.update(TESTING=True)
    return module


@pytest.fixture
def app_module(tmp_path):
    return _load_app(tmp_path, configured=True)


@pytest.fixture
def client(app_module):
    return app_module.app.test_client()


@pytest.fixture
def unconfigured(tmp_path):
    return _load_app(tmp_path, configured=False)


@pytest.fixture
def behind_one_proxy(tmp_path):
    return _load_app(tmp_path, configured=True, trusted_proxies=1)


@pytest.fixture
def load_app(tmp_path):
    # Para tests que necesitan otra configuracion (p. ej. topes chicos).
    def load(**env):
        return _load_app(tmp_path, configured=True, env=env)
    return load
