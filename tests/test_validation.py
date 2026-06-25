"""Input Validation

Verifies server-side validation on all user-supplied fields:
- Issue title and description are required
- Severity must be exactly Low / Medium / High
- Status must be exactly Open / In Progress / Closed
- Registration requires username (≤50 chars) and password (≥8 chars)
- Duplicate usernames are rejected
"""

from tests.conftest import register, register_and_login, create_issue


class TestIssueValidation:

    def test_empty_title_rejected(self, client):
        register_and_login(client)
        resp = create_issue(client, title='', follow_redirects=True)
        assert b'Title is required' in resp.data

    def test_whitespace_only_title_rejected(self, client):
        register_and_login(client)
        resp = create_issue(client, title='   ', follow_redirects=True)
        assert b'Title is required' in resp.data

    def test_empty_description_rejected(self, client):
        register_and_login(client)
        resp = create_issue(client, description='', follow_redirects=True)
        assert b'Description is required' in resp.data

    def test_invalid_severity_rejected(self, client):
        register_and_login(client)
        resp = create_issue(client, severity='Critical', follow_redirects=True)
        assert b'Severity must be one of' in resp.data

    def test_invalid_status_rejected(self, client):
        register_and_login(client)
        resp = create_issue(client, status='Urgent', follow_redirects=True)
        assert b'Status must be one of' in resp.data

    def test_valid_issue_creates_and_redirects(self, client):
        register_and_login(client)
        resp = create_issue(
            client,
            title='Valid Issue',
            description='A real description',
            severity='High',
            status='In Progress',
        )
        # Successful creation redirects to dashboard
        assert resp.status_code == 302
        assert '/dashboard' in resp.headers['Location']

    def test_all_valid_severities_accepted(self, client):
        register_and_login(client)
        for sev in ('Low', 'Medium', 'High'):
            resp = create_issue(client, title=f'Issue {sev}', severity=sev)
            assert resp.status_code == 302

    def test_all_valid_statuses_accepted(self, client):
        register_and_login(client)
        for status in ('Open', 'In Progress', 'Closed'):
            resp = create_issue(client, title=f'Issue {status}', status=status)
            assert resp.status_code == 302


class TestRegistrationValidation:

    def test_short_password_rejected(self, client):
        resp = client.post(
            '/register',
            data={'username': 'alice', 'password': 'short'},
            follow_redirects=True,
        )
        assert b'at least 8 characters' in resp.data

    def test_empty_username_rejected(self, client):
        resp = client.post(
            '/register',
            data={'username': '', 'password': 'Password123'},
            follow_redirects=True,
        )
        assert b'Username is required' in resp.data

    def test_empty_password_rejected(self, client):
        resp = client.post(
            '/register',
            data={'username': 'alice', 'password': ''},
            follow_redirects=True,
        )
        assert b'Password is required' in resp.data

    def test_duplicate_username_rejected(self, client):
        register(client, 'alice', 'Password123')
        client.get('/logout')  # register auto-logs in; clear session before second attempt
        resp = client.post(
            '/register',
            data={'username': 'alice', 'password': 'AnotherPass123'},
            follow_redirects=True,
        )
        assert b'already taken' in resp.data

    def test_username_too_long_rejected(self, client):
        long_name = 'a' * 51
        resp = client.post(
            '/register',
            data={'username': long_name, 'password': 'Password123'},
            follow_redirects=True,
        )
        assert b'50 characters' in resp.data
