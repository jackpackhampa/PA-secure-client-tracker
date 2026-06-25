import sqlite3
import pytest
import app as app_module
from app import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    """Single test client with an isolated temp database.

    Not used as a context manager — Flask 3.x sets preserve_context=True
    inside `with test_client()`, which conflicts when two clients interleave
    requests against the same app's context stack.
    """
    db = str(tmp_path / 'test.db')
    monkeypatch.setattr(app_module, 'DATABASE', db)
    app.config.update({'TESTING': True, 'WTF_CSRF_ENABLED': False})
    with app.app_context():
        app_module.init_db()
    yield app.test_client()


@pytest.fixture
def two_clients(monkeypatch, tmp_path):
    """Two independent clients sharing one temp database.

    Required for cross-user access-control tests: User A and User B must
    coexist in the same DB while holding separate session cookies.

    Intentionally NOT used as context managers — Flask 3.x's
    preserve_context=True causes "Popped wrong request context" when two
    clients interleave requests against the same app.
    """
    db = str(tmp_path / 'shared.db')
    monkeypatch.setattr(app_module, 'DATABASE', db)
    app.config.update({'TESTING': True, 'WTF_CSRF_ENABLED': False})
    with app.app_context():
        app_module.init_db()
    yield app.test_client(), app.test_client()


@pytest.fixture
def csrf_client(monkeypatch, tmp_path):
    """Test client with CSRF protection enabled (A05 tests only)."""
    db = str(tmp_path / 'csrf.db')
    monkeypatch.setattr(app_module, 'DATABASE', db)
    app.config.update({'TESTING': True, 'WTF_CSRF_ENABLED': True})
    with app.app_context():
        app_module.init_db()
    yield app.test_client(use_cookies=True)
    # Restore so subsequent tests in the session are not affected
    app.config['WTF_CSRF_ENABLED'] = False


# ---------------------------------------------------------------------------
# Helper functions (not fixtures — call directly from tests)
# ---------------------------------------------------------------------------

def register(client, username='alice', password='Password123'):
    """Register a user. Does not assert on the response."""
    return client.post(
        '/register',
        data={'username': username, 'password': password},
    )


def login(client, username='alice', password='Password123'):
    """Log a user in. Does not assert on the response."""
    return client.post(
        '/login',
        data={'username': username, 'password': password},
    )


def register_and_login(client, username='alice', password='Password123'):
    """Register then immediately log in."""
    register(client, username, password)
    login(client, username, password)


def create_issue(client, title='Test Issue', description='Test description',
                 severity='Medium', status='Open', follow_redirects=False):
    """Create an issue and return the response."""
    return client.post(
        '/issues/new',
        data={
            'title': title,
            'description': description,
            'severity': severity,
            'status': status,
        },
        follow_redirects=follow_redirects,
    )


def open_db():
    """Return a raw sqlite3 connection to the current DATABASE path.

    Only valid inside a test that has already monkeypatched DATABASE.
    Caller is responsible for closing.
    """
    conn = sqlite3.connect(app_module.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn
