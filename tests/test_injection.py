"""OWASP A03 — SQL Injection

Verifies that:
- SQL injection payloads in the login form do not bypass authentication
- SQL injection payloads in issue fields are stored as literal text (not executed)
- The database schema remains intact after injection attempts
"""

from tests.conftest import register_and_login, open_db


class TestLoginSQLInjection:

    def test_classic_or_injection_does_not_bypass_login(self, client):
        resp = client.post(
            '/login',
            data={"username": "' OR '1'='1", "password": "' OR '1'='1"},
            follow_redirects=True,
        )
        assert b'Invalid username or password' in resp.data

    def test_injected_login_does_not_establish_session(self, client):
        client.post(
            '/login',
            data={"username": "' OR '1'='1", "password": "' OR '1'='1"},
        )
        resp = client.get('/dashboard')
        # Still redirected — no session was established
        assert resp.status_code == 302

    def test_comment_injection_in_username_does_not_bypass(self, client):
        resp = client.post(
            '/login',
            data={'username': "admin'--", 'password': 'anything'},
            follow_redirects=True,
        )
        assert b'Invalid username or password' in resp.data


class TestIssueFieldSQLInjection:

    def test_drop_table_payload_in_title_stored_as_literal(self, client):
        register_and_login(client)
        payload = "'; DROP TABLE issues; --"
        client.post('/issues/new', data={
            'title': payload,
            'description': 'desc',
            'severity': 'Low',
            'status': 'Open',
        })

        db = open_db()
        row = db.execute(
            'SELECT title FROM issues WHERE title = ?', (payload,)
        ).fetchone()
        db.close()

        assert row is not None, 'Payload was not stored — possible injection executed'
        assert row['title'] == payload

    def test_issues_table_survives_drop_payload(self, client):
        register_and_login(client)
        client.post('/issues/new', data={
            'title': "'; DROP TABLE issues; --",
            'description': 'desc',
            'severity': 'Low',
            'status': 'Open',
        })

        db = open_db()
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='issues'"
        ).fetchone()
        db.close()

        assert tables is not None, 'issues table was dropped — SQL injection succeeded'

    def test_union_payload_in_description_stored_safely(self, client):
        register_and_login(client)
        payload = "' UNION SELECT username, password_hash, 1, 2, 3, 4, 5 FROM users --"
        client.post('/issues/new', data={
            'title': 'Union test',
            'description': payload,
            'severity': 'Low',
            'status': 'Open',
        })

        resp = client.get('/issues/1', follow_redirects=True)
        assert resp.status_code == 200
        # The page must not expose any password hashes
        db = open_db()
        user = db.execute('SELECT password_hash FROM users').fetchone()
        db.close()
        if user:
            assert user['password_hash'].encode() not in resp.data
