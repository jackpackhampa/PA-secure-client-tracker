"""OWASP A03 — Cross-Site Scripting (XSS)

Verifies that Jinja2 auto-escaping prevents user-supplied HTML/JS from being
rendered as raw markup on the issue detail, dashboard list, and edit pages.
"""

from tests.conftest import register_and_login, create_issue


class TestXSSInIssueDescription:

    def test_script_tag_escaped_on_detail_page(self, client):
        register_and_login(client)
        xss = '<script>alert("xss")</script>'
        create_issue(client, description=xss)

        resp = client.get('/issues/1', follow_redirects=True)
        assert b'<script>alert' not in resp.data
        assert b'&lt;script&gt;' in resp.data

    def test_img_onerror_escaped_in_description(self, client):
        register_and_login(client)
        xss = '<img src=x onerror=alert(1)>'
        create_issue(client, description=xss)

        resp = client.get('/issues/1', follow_redirects=True)
        assert b'<img src=x onerror' not in resp.data

    def test_event_handler_attribute_escaped_in_description(self, client):
        register_and_login(client)
        xss = '<a href="#" onclick="stealCookies()">click me</a>'
        create_issue(client, description=xss)

        resp = client.get('/issues/1', follow_redirects=True)
        assert b'onclick="stealCookies' not in resp.data


class TestXSSInIssueTitle:

    def test_script_tag_in_title_escaped_on_dashboard(self, client):
        register_and_login(client)
        xss = '<script>alert("xss")</script>'
        create_issue(client, title=xss)

        resp = client.get('/dashboard', follow_redirects=True)
        assert b'<script>alert' not in resp.data
        assert b'&lt;script&gt;' in resp.data

    def test_img_onerror_in_title_escaped_on_dashboard(self, client):
        register_and_login(client)
        xss = '<img src=x onerror=alert(1)>'
        create_issue(client, title=xss)

        resp = client.get('/dashboard', follow_redirects=True)
        assert b'<img src=x onerror' not in resp.data

    def test_script_tag_in_title_escaped_on_detail_page(self, client):
        register_and_login(client)
        xss = '<script>alert("title-xss")</script>'
        create_issue(client, title=xss)

        resp = client.get('/issues/1', follow_redirects=True)
        assert b'<script>alert("title-xss")' not in resp.data
        assert b'&lt;script&gt;' in resp.data

    def test_script_tag_in_title_escaped_on_edit_page(self, client):
        register_and_login(client)
        xss = '<script>alert("edit-xss")</script>'
        create_issue(client, title=xss)

        resp = client.get('/issues/1/edit', follow_redirects=True)
        assert b'<script>alert("edit-xss")' not in resp.data
