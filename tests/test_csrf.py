"""OWASP A05 — Security Misconfiguration / CSRF

Verifies that:
- POST requests without a valid CSRF token are rejected with 400
- POST requests with a valid CSRF token are accepted and processed normally

Uses the `csrf_client` fixture which runs the app with WTF_CSRF_ENABLED=True.
All other test modules use CSRF disabled so they can POST without tokens.
"""

import re
import sqlite3

import app as app_module
from werkzeug.security import generate_password_hash
from tests.conftest import open_db


def _extract_csrf_token(html: bytes) -> str:
    """Parse the hidden csrf_token value from a rendered HTML page."""
    match = re.search(rb'name="csrf_token"\s+value="([^"]+)"', html)
    assert match, 'CSRF token not found in page HTML'
    return match.group(1).decode()


class TestCSRFProtection:

    def test_login_post_without_token_returns_400(self, csrf_client):
        resp = csrf_client.post(
            '/login',
            data={'username': 'alice', 'password': 'Password123'},
        )
        assert resp.status_code == 400

    def test_register_post_without_token_returns_400(self, csrf_client):
        resp = csrf_client.post(
            '/register',
            data={'username': 'alice', 'password': 'Password123'},
        )
        assert resp.status_code == 400

    def test_login_post_with_valid_token_is_not_rejected(self, csrf_client):
        """A request with a valid token must NOT get a 400 — it proceeds to auth logic."""
        page = csrf_client.get('/login')
        token = _extract_csrf_token(page.data)

        resp = csrf_client.post(
            '/login',
            data={'username': 'nobody', 'password': 'x', 'csrf_token': token},
            follow_redirects=True,
        )
        # Auth fails (user doesn't exist) but CSRF is satisfied — not 400
        assert resp.status_code == 200
        assert b'Invalid username or password' in resp.data

    def test_register_post_with_valid_token_is_not_rejected(self, csrf_client):
        page = csrf_client.get('/register')
        token = _extract_csrf_token(page.data)

        resp = csrf_client.post(
            '/register',
            data={'username': 'newuser', 'password': 'ValidPass123', 'csrf_token': token},
        )
        # Should redirect (302) or re-render with a validation error — not 400
        assert resp.status_code != 400

    def test_delete_post_without_token_returns_400(self, csrf_client):
        """Delete route must also require a CSRF token.

        We seed the DB directly and inject a session so we can reach the route
        without going through the full registration flow (which also needs tokens).
        """
        db = open_db()
        pw_hash = generate_password_hash('Password123', method='pbkdf2:sha256')
        db.execute('INSERT INTO users (username, password_hash) VALUES (?,?)',
                   ('alice', pw_hash))
        db.commit()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            'INSERT INTO issues (title, description, severity, status, user_id, created_at, updated_at)'
            ' VALUES (?,?,?,?,?,?,?)',
            ('My issue', 'desc', 'Low', 'Open', 1, now, now),
        )
        db.commit()
        db.close()

        with csrf_client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'alice'

        resp = csrf_client.post('/issues/1/delete')
        assert resp.status_code == 400

    def test_new_issue_post_without_token_returns_400(self, csrf_client):
        db = open_db()
        pw_hash = generate_password_hash('Password123', method='pbkdf2:sha256')
        db.execute('INSERT INTO users (username, password_hash) VALUES (?,?)',
                   ('alice', pw_hash))
        db.commit()
        db.close()

        with csrf_client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'alice'

        resp = csrf_client.post('/issues/new', data={
            'title': 'x', 'description': 'y', 'severity': 'Low', 'status': 'Open',
        })
        assert resp.status_code == 400
