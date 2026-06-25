"""OWASP A01 — Broken Access Control

Verifies that:
- One user cannot view, edit, or delete another user's issues by manipulating URLs/IDs
- Unauthenticated users are redirected to /login on all protected routes
"""

from tests.conftest import register_and_login, create_issue, open_db


class TestCrossUserIsolation:
    """User A's issues must not be reachable by User B."""

    def _setup(self, two_clients):
        """User A registers, creates issue #1. User B registers. Returns (ca, cb)."""
        ca, cb = two_clients
        register_and_login(ca, 'user_a', 'PasswordA123')
        create_issue(ca, title='User A secret issue')
        register_and_login(cb, 'user_b', 'PasswordB123')
        return ca, cb

    def test_cannot_view_another_users_issue(self, two_clients):
        _, cb = self._setup(two_clients)
        resp = cb.get('/issues/1')
        assert resp.status_code == 403

    def test_cannot_get_edit_form_for_another_users_issue(self, two_clients):
        _, cb = self._setup(two_clients)
        resp = cb.get('/issues/1/edit')
        assert resp.status_code == 403

    def test_cannot_post_edit_to_another_users_issue(self, two_clients):
        _, cb = self._setup(two_clients)
        resp = cb.post('/issues/1/edit', data={
            'title': 'Hijacked',
            'description': 'Evil edit',
            'severity': 'High',
            'status': 'Open',
        })
        assert resp.status_code == 403

    def test_cannot_delete_another_users_issue(self, two_clients):
        _, cb = self._setup(two_clients)
        resp = cb.post('/issues/1/delete')
        assert resp.status_code == 403

    def test_issue_unchanged_after_failed_cross_user_edit(self, two_clients):
        """Confirm the DB row was not modified despite the 403.

        Verifies via direct DB query rather than HTTP to avoid Flask 3.x
        request-context conflicts between interleaved two-client requests.
        """
        _, cb = self._setup(two_clients)
        cb.post('/issues/1/edit', data={
            'title': 'Hijacked',
            'description': 'Evil edit',
            'severity': 'High',
            'status': 'Closed',
        })
        db = open_db()
        row = db.execute('SELECT title FROM issues WHERE id = 1').fetchone()
        db.close()
        assert row is not None
        assert row['title'] == 'User A secret issue'

    def test_issue_still_exists_after_failed_cross_user_delete(self, two_clients):
        """Confirm the issue was not deleted despite the 403."""
        _, cb = self._setup(two_clients)
        cb.post('/issues/1/delete')
        db = open_db()
        row = db.execute('SELECT id FROM issues WHERE id = 1').fetchone()
        db.close()
        assert row is not None


class TestUnauthenticatedAccess:
    """All protected routes must redirect to /login when no session exists."""

    def test_dashboard_redirects_to_login(self, client):
        resp = client.get('/dashboard')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_new_issue_get_redirects_to_login(self, client):
        resp = client.get('/issues/new')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_new_issue_post_redirects_to_login(self, client):
        resp = client.post('/issues/new', data={
            'title': 'x', 'description': 'x', 'severity': 'Low', 'status': 'Open',
        })
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_view_issue_redirects_to_login(self, client):
        resp = client.get('/issues/1')
        assert resp.status_code == 302

    def test_edit_issue_redirects_to_login(self, client):
        resp = client.get('/issues/1/edit')
        assert resp.status_code == 302

    def test_delete_issue_redirects_to_login(self, client):
        resp = client.post('/issues/1/delete')
        assert resp.status_code == 302
