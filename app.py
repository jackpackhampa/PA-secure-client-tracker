import sqlite3
import os
from functools import wraps
from datetime import datetime, timezone

from flask import (
    Flask, g, session, redirect, url_for, render_template,
    request, flash, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-in-production')
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

csrf = CSRFProtect(app)

DATABASE = os.path.join(app.instance_path, 'tracker.db')

VALID_SEVERITIES = ('Low', 'Medium', 'High')
VALID_STATUSES = ('Open', 'In Progress', 'Closed')


# Database helpers

def get_db():
    if 'db' not in g:
        os.makedirs(app.instance_path, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High')),
            status TEXT NOT NULL DEFAULT 'Open'
                CHECK(status IN ('Open','In Progress','Closed')),
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    db.commit()


@app.cli.command('init-db')
def init_db_command():
    init_db()
    print('Database initialised.')


with app.app_context():
    init_db()


# Auth decorator

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# Auth routes

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        errors = []
        if not username:
            errors.append('Username is required.')
        elif len(username) > 50:
            errors.append('Username must be 50 characters or fewer.')
        if not password:
            errors.append('Password is required.')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters.')

        if not errors:
            db = get_db()
            existing = db.execute(
                'SELECT id FROM users WHERE username = ?', (username,)
            ).fetchone()
            if existing:
                errors.append('Username already taken.')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html', username=username)

        db = get_db()
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, password_hash)
        )
        db.commit()
        user = db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        session.clear()
        session['user_id'] = user['id']
        session['username'] = username
        flash('Account created. Welcome!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('auth/register.html', username='')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        if user is None or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'error')
            return render_template('auth/login.html', username=username)

        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        return redirect(url_for('dashboard'))

    return render_template('auth/login.html', username='')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Issue routes

@app.route('/dashboard')
@login_required
def dashboard():
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')

    if severity not in VALID_SEVERITIES:
        severity = ''
    if status not in VALID_STATUSES:
        status = ''

    db = get_db()
    query = 'SELECT * FROM issues WHERE user_id = ?'
    params = [session['user_id']]
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    if status:
        query += ' AND status = ?'
        params.append(status)
    query += ' ORDER BY created_at DESC'
    issues = db.execute(query, params).fetchall()

    return render_template(
        'issues/list.html',
        issues=issues,
        valid_severities=VALID_SEVERITIES,
        valid_statuses=VALID_STATUSES,
        current_severity=severity,
        current_status=status,
    )


@app.route('/issues/new', methods=['GET', 'POST'])
@login_required
def new_issue():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', '')
        status = request.form.get('status', 'Open')

        errors = _validate_issue(title, description, severity, status)
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template(
                'issues/form.html',
                mode='create',
                form_action=url_for('new_issue'),
                values={'title': title, 'description': description,
                        'severity': severity, 'status': status},
                valid_severities=VALID_SEVERITIES,
                valid_statuses=VALID_STATUSES,
            )

        now = datetime.now(timezone.utc).isoformat()
        db = get_db()
        db.execute(
            'INSERT INTO issues (title, description, severity, status, user_id, created_at, updated_at)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            (title, description, severity, status, session['user_id'], now, now)
        )
        db.commit()
        flash('Issue created.', 'success')
        return redirect(url_for('dashboard'))

    return render_template(
        'issues/form.html',
        mode='create',
        form_action=url_for('new_issue'),
        values={'title': '', 'description': '', 'severity': 'Medium', 'status': 'Open'},
        valid_severities=VALID_SEVERITIES,
        valid_statuses=VALID_STATUSES,
    )


@app.route('/issues/<int:id>')
@login_required
def view_issue(id):
    db = get_db()
    issue = db.execute(
        'SELECT * FROM issues WHERE id = ? AND user_id = ?',
        (id, session['user_id'])
    ).fetchone()
    if issue is None:
        abort(403)
    return render_template('issues/detail.html', issue=issue)


@app.route('/issues/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_issue(id):
    db = get_db()
    issue = db.execute(
        'SELECT * FROM issues WHERE id = ? AND user_id = ?',
        (id, session['user_id'])
    ).fetchone()
    if issue is None:
        abort(403)

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        severity = request.form.get('severity', '')
        status = request.form.get('status', '')

        errors = _validate_issue(title, description, severity, status)
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template(
                'issues/form.html',
                mode='edit',
                form_action=url_for('edit_issue', id=id),
                values={'title': title, 'description': description,
                        'severity': severity, 'status': status},
                valid_severities=VALID_SEVERITIES,
                valid_statuses=VALID_STATUSES,
            )

        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            'UPDATE issues SET title=?, description=?, severity=?, status=?, updated_at=?'
            ' WHERE id=? AND user_id=?',
            (title, description, severity, status, now, id, session['user_id'])
        )
        db.commit()
        flash('Issue updated.', 'success')
        return redirect(url_for('view_issue', id=id))

    return render_template(
        'issues/form.html',
        mode='edit',
        form_action=url_for('edit_issue', id=id),
        values=dict(issue),
        valid_severities=VALID_SEVERITIES,
        valid_statuses=VALID_STATUSES,
    )


@app.route('/issues/<int:id>/delete', methods=['POST'])
@login_required
def delete_issue(id):
    db = get_db()
    result = db.execute(
        'DELETE FROM issues WHERE id = ? AND user_id = ?',
        (id, session['user_id'])
    )
    db.commit()
    if result.rowcount == 0:
        abort(403)
    flash('Issue deleted.', 'success')
    return redirect(url_for('dashboard'))


# Validation helper

def _validate_issue(title, description, severity, status):
    errors = []
    if not title:
        errors.append('Title is required.')
    if not description:
        errors.append('Description is required.')
    if severity not in VALID_SEVERITIES:
        errors.append(f'Severity must be one of: {", ".join(VALID_SEVERITIES)}.')
    if status not in VALID_STATUSES:
        errors.append(f'Status must be one of: {", ".join(VALID_STATUSES)}.')
    return errors


# Error handlers

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404


if __name__ == '__main__':
    app.run(debug=False)
