"""OWASP A07 — Authentication Failures

Verifies that:
- Failed logins always return a generic error (no username-enumeration oracle)
- Protected routes redirect unauthenticated users to /login
- Successful login establishes a session
- Logout destroys the session
"""

from tests.conftest import register, register_and_login, login

GENERIC_ERROR = b'Invalid username or password'


class TestLoginErrorMessages:

    def test_wrong_password_shows_generic_error(self, client):
        register(client, 'alice', 'RightPass123')
        client.get('/logout')  # register auto-logs in; clear session before testing login errors
        resp = client.post(
            '/login',
            data={'username': 'alice', 'password': 'WrongPass999'},
            follow_redirects=True,
        )
        assert GENERIC_ERROR in resp.data

    def test_wrong_password_does_not_reveal_password_hint(self, client):
        register(client, 'alice', 'RightPass123')
        client.get('/logout')
        resp = client.post(
            '/login',
            data={'username': 'alice', 'password': 'WrongPass999'},
            follow_redirects=True,
        )
        assert b'wrong password' not in resp.data.lower()
        assert b'incorrect password' not in resp.data.lower()

    def test_nonexistent_user_shows_same_generic_error(self, client):
        """No oracle: the error for a missing username must be identical."""
        resp = client.post(
            '/login',
            data={'username': 'nobody', 'password': 'whatever'},
            follow_redirects=True,
        )
        assert GENERIC_ERROR in resp.data

    def test_nonexistent_user_does_not_say_user_not_found(self, client):
        resp = client.post(
            '/login',
            data={'username': 'nobody', 'password': 'whatever'},
            follow_redirects=True,
        )
        assert b'not found' not in resp.data.lower()
        assert b'does not exist' not in resp.data.lower()


class TestProtectedRoutes:

    def test_dashboard_requires_login(self, client):
        resp = client.get('/dashboard')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_new_issue_requires_login(self, client):
        resp = client.get('/issues/new')
        assert resp.status_code == 302

    def test_view_issue_requires_login(self, client):
        resp = client.get('/issues/42')
        assert resp.status_code == 302

    def test_edit_issue_requires_login(self, client):
        resp = client.get('/issues/42/edit')
        assert resp.status_code == 302


class TestSessionLifecycle:

    def test_successful_login_redirects_to_dashboard(self, client):
        register(client, 'alice', 'Password123')
        resp = client.post(
            '/login',
            data={'username': 'alice', 'password': 'Password123'},
        )
        assert resp.status_code == 302
        assert '/dashboard' in resp.headers['Location']

    def test_logged_in_user_can_access_dashboard(self, client):
        register_and_login(client)
        resp = client.get('/dashboard')
        assert resp.status_code == 200

    def test_logout_redirects_to_login(self, client):
        register_and_login(client)
        resp = client.get('/logout')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_dashboard_inaccessible_after_logout(self, client):
        register_and_login(client)
        client.get('/logout')
        resp = client.get('/dashboard')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']
