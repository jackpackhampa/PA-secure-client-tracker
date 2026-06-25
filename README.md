# Secure Client Feedback Tracker

A lightweight internal web application for consultants to log and manage structured client feedback, issues, risks, and stakeholder concerns. Think of it as a minimal Jira/ServiceNow-style tracker with OWASP-aware security.

## Tech Stack

- **Python 3.10+** with **Flask 3**
- **SQLite** via the Python standard library (`sqlite3`)
- **Werkzeug** — password hashing
- **Flask-WTF** — CSRF protection

---

## Setup

```bash
# 1. Clone the repo
git clone <repo-url>
cd PA-secure-client-tracker

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set a secret key (required for production; dev fallback is set automatically)
export SECRET_KEY='your-long-random-secret-key-here'

# 5. Run the app
flask run
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

The SQLite database (`instance/tracker.db`) is created automatically on first run — no migration step needed.

---

## Features

- Register, log in, and log out
- Create, view, edit, and delete feedback/issue entries
- Each issue tracks: title, description, severity (Low / Medium / High), and status (Open / In Progress / Closed)
- Filter your dashboard by severity or status
- Users can only see and manage their own issues

---

## Security Features

| Feature | Implementation |
|---|---|
| **Password hashing** | Werkzeug `generate_password_hash` (PBKDF2-SHA256 with salt) — plaintext passwords are never stored |
| **SQL injection prevention** | All database queries use `?` parameterised placeholders — no string interpolation in SQL |
| **XSS prevention** | Jinja2 auto-escaping is enabled by default for all `.html` templates — user content is HTML-escaped before rendering |
| **CSRF protection** | Flask-WTF `CSRFProtect` validates a hidden token on every state-mutating POST request |
| **Access control** | Every issue query includes `WHERE user_id = ?` scoped to the session user; `abort(403)` on any mismatch |
| **Session fixation prevention** | `session.clear()` is called before setting new session data on login |
| **Username enumeration prevention** | Login always returns the same generic message on failure regardless of whether the username exists |
| **Input validation** | Server-side: title/description required, severity/status validated against an allowlist — client-side validation is disabled (`novalidate`) so server responses are always visible |
| **Delete via POST only** | Delete actions require a POST form with a CSRF token, preventing CSRF-via-link |

---

## OWASP Test Cases

These can be demonstrated manually to validate the security posture:

| OWASP Category | Test | Expected Result |
|---|---|---|
| **A01 — Broken Access Control** | Log in as User A. Note an issue ID. Log in as User B. Navigate to `/issues/<User A's ID>` | **403 Forbidden** |
| **A01 — Broken Access Control** | As User B, POST to `/issues/<User A's ID>/delete` | **403 Forbidden** (0 rows affected) |
| **A02 — Cryptographic Failures** | Inspect `instance/tracker.db`: `sqlite3 instance/tracker.db "SELECT * FROM users;"` | Password column contains a hashed value — never plaintext |
| **A03 — Injection (SQL)** | In the login form, enter username: `' OR '1'='1` | Login fails safely; no bypass |
| **A03 — Injection (SQL)** | Create an issue with title: `'; DROP TABLE issues; --` | Stored as literal text; `issues` table still exists |
| **A03 — XSS** | Create an issue with description: `<script>alert('xss')</script>` | Rendered as escaped text (`&lt;script&gt;...`) — no alert fires |
| **A05 — Security Misconfiguration** | Use browser dev tools or `curl` to remove the `csrf_token` field from a POST body | Flask-WTF returns **400 Bad Request** |
| **A07 — Auth Failures** | Submit the login form with a correct username and wrong password | Generic error: *"Invalid username or password."* |
| **A07 — Auth Failures** | Navigate to `/dashboard` without a session cookie | Redirected to `/login` |
| **A03 — Invalid input** | Submit an issue form with `severity=Critical` via curl or browser dev tools | Server rejects it with a validation error |

---

## Project Structure

```
PA-secure-client-tracker/
├── app.py                  # Flask application — routes, auth, DB helpers
├── requirements.txt
├── README.md
├── instance/
│   └── tracker.db          # SQLite database (auto-created)
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── auth/
    │   ├── login.html
    │   └── register.html
    ├── issues/
    │   ├── list.html       # Dashboard with filter bar
    │   ├── detail.html     # Issue detail view
    │   └── form.html       # Shared create/edit form
    └── errors/
        ├── 403.html
        └── 404.html
```

---

## Notes for DevOps Extension

The app is structured to support future additions:

- **Environment variables**: `SECRET_KEY` is already read from the environment
- **Database path**: `DATABASE` uses `app.instance_path` — works cleanly with Docker volume mounts
- **No hardcoded config**: all tuneable values are at the top of `app.py`
- Add a `Dockerfile`, `docker-compose.yml`, or a `gunicorn` entry point for production deployment
- Replace the SQLite file with Postgres by swapping the `get_db()` helper and connection string
