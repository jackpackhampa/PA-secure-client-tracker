"""OWASP A02 — Cryptographic Failures

Verifies that:
- Passwords are never stored in plaintext
- The hashing algorithm is PBKDF2-SHA256 (Werkzeug default)
- Salt is applied: two users with the same password receive different hashes
"""

from tests.conftest import register, open_db


class TestPasswordStorage:

    def test_password_not_stored_in_plaintext(self, client):
        raw = 'MySecret123'
        register(client, 'alice', raw)

        db = open_db()
        row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
        db.close()

        assert row is not None
        assert row['password_hash'] != raw

    def test_password_hash_uses_pbkdf2_sha256(self, client):
        register(client, 'alice', 'MySecret123')

        db = open_db()
        row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
        db.close()

        assert row['password_hash'].startswith('pbkdf2:sha256')

    def test_hash_is_not_md5_or_sha1(self, client):
        register(client, 'alice', 'MySecret123')

        db = open_db()
        row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
        db.close()

        h = row['password_hash']
        assert not h.startswith('md5')
        assert not h.startswith('sha1')

    def test_same_password_produces_different_hashes(self, two_clients):
        """Salt must differ per user: identical passwords must hash differently."""
        ca, cb = two_clients
        shared_password = 'SharedPass123'
        register(ca, 'alice', shared_password)
        register(cb, 'bob', shared_password)

        db = open_db()
        alice = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
        bob = db.execute("SELECT password_hash FROM users WHERE username='bob'").fetchone()
        db.close()

        assert alice['password_hash'] != bob['password_hash']
