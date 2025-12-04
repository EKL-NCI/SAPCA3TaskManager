import logging
import re
import sqlite3
import os
import bleach

from logging.handlers import RotatingFileHandler
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, g, abort
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_talisman import Talisman
from flask_bootstrap import Bootstrap5
from functools import wraps

# --- Flask App Initialization ---
app = Flask(__name__)
bootstrap = Bootstrap5(app)
bcrypt = Bcrypt(app)

# Secret key for CSRF (Need to change)
app.config['SECRET_KEY'] = 'your_secret_key'

# Session security config
app.config.update(
    # Should be set to true in production
    SESSION_COOKIE_SECURE=False,
    # Protects against stolen cookies
    SESSION_COOKIE_HTTPONLY=True,
    # Helps mitigate CSRF
    SESSION_COOKIE_SAMESITE="Lax",
    # Session Timeout
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

DATABASE = "secure_db.db"

# Security headers - protects against XSS (Allow bootstrap)
Talisman(app, content_security_policy={
    "default-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
})

# Enable CSRF protection
csrf = CSRFProtect(app)

# Initialize login manager to handle sessions
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --- Database ---
# Creates or returns existing db
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

# Close database connection after request is completed
@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# --- Logging ---
LOG_FILEPATH = "logs/secure_app.log"

# Creates folder for logs if not already created
if not os.path.exists("logs"):
    os.makedirs("logs")

# Creates a secure_app.log if not already created
# Configure how large files should be and how many should be kept
file_handler = RotatingFileHandler(
    LOG_FILEPATH, maxBytes=2_000_000, backupCount=5
)

file_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))

file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# --- User configurations ---
# User class for flask-login
class User(UserMixin):
    def __init__(self, id_, username, email, role='user', isLocked=0, failed_login_count=0):
        self.id = id_
        self.username = username
        self.email = email
        self.role = role
        self.isLocked = isLocked
        self.failed_login_count = failed_login_count

        @property
        def is_active(self):
            # User is only active if account is not locked
            return not self.isLocked

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute(
        "SELECT ID, username, email, role, isLocked, failed_login_count FROM users WHERE ID = ?",
        (user_id,)
    ).fetchone()

    if row:
        return User(
            id_=row["ID"],
            username=row["username"],
            email=row["email"],
            role=row["role"],
            isLocked=row["isLocked"],
            failed_login_count=row["failed_login_count"]
        )
    return None

# Admin Role
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role == 'admin':
            return f(*args, **kwargs)
    
        app.logger.warning(f"Unauthorized admin access attempt by User ID: {current_user.id} ({current_user.username})")
        abort(403)
    return decorated_function

def get_recent_logs(n=20):
    if not os.path.exists(LOG_FILEPATH):
        app.logger.error(f"Log file not found at: {LOG_FILEPATH}")
        return []

    try:
        with open(LOG_FILEPATH, 'r') as f:
            lines = f.readlines()

        recent_lines = lines[-n:][::-1]

        logs = []
        for line in recent_lines:
            # Log format: YYYY-MM-DD HH:MM:SS,ms - LEVEL - Message
            parts = line.split(' - ', 2)
            if len(parts) == 3:
                time_part = parts[0].split(',')[0]
                level = parts[1].strip()
                message = parts[2].strip()

                logs.append({
                    'time': time_part,
                    'level': level,
                    'message': message
                })
        return logs
    except Exception as e:
        app.logger.error(f"Error reading log file: {e}")
        return [{'time': 'N/A', 'level': 'ERROR', 'message': f'Failed to read log file: {e}'}]

# --- Flask Routes ---
# Basic home route
@app.route("/")
def home():
    return render_template("index.html")

# Login Route: Secure
@app.route("/login", methods=["GET", "POST"])
def login():
    user_row = None

    if request.method == "POST":
        # Plain text passwords
        identifier = request.form["username_or_email"]
        password = request.form["password"]

        db = get_db()
        user_row = db.execute(
            "SELECT ID, username, email, pass_hash, role, isLocked, failed_login_count "
            "FROM users WHERE username = ? OR email = ?",
            (identifier, identifier)
        ).fetchone()

        if user_row:
            user = User(
                user_row["ID"], user_row["username"], user_row["email"],
                user_row["role"], user_row["isLocked"], user_row["failed_login_count"]
            )

            if user.isLocked:
                app.logger.warning(f"Failed login: Account {user.username} is locked.")
                flash("This account has been locked due to too many failed attempts.", "danger")
                return render_template("login.html")

            if bcrypt.check_password_hash(user_row["pass_hash"], password):
                db.execute(
                    "UPDATE users SET failed_login_count = 0 WHERE ID = ?",
                    (user.id,)
                )
                db.commit()

                login_user(user)
                app.logger.info(f"Successful login: {user.username}")
                return redirect(url_for("tasks"))
            else:
                new_fail_count = user.failed_login_count + 1

                if new_fail_count >= 5:
                    db.execute(
                        "UPDATE users SET failed_login_count = ?, isLocked = 1 WHERE ID = ?",
                        (new_fail_count, user.id)
                    )
                    app.logger.critical(f"ACCOUNT LOCKED: {user.username} due to 5+ failed attempts.")
                    flash("Invalid credentials. Your account has been locked. Please contact an administrator", "danger")
                else:
                    db.execute(
                        "UPDATE users SET failed_login_count = ? WHERE ID = ?",
                        (new_fail_count, user.id)
                    )
                    app.logger.warning(f"Failed login attempt ({new_fail_count}/5): {identifier}")
                    flash("Invalid login credentials", "danger")
                db.commit()
        else:
            app.logger.warning(f"Failed login attempt for unknown identifier: {identifier}")
            flash("Invalid login credentials", "danger")

    return render_template("login.html")

# Logout Route
# Log out current user and end session
@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        app.logger.info(f"Logged out: {current_user.username}")
    else:
        app.logger.info("Logged out an unauthenticated session.")
    logout_user()
    return redirect('/')

# Register Route: Secure
# User registration with hashed passwords
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$"

        if not re.match(PASSWORD_REGEX, password):
            flash("Password must be at least 8 characters long, include one uppercase letter, one lowercase letter and one special character (e.g., !, @, #).", "danger")
            return render_template("register.html")

        pass_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, pass_hash, role, isLocked, failed_login_count) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, pass_hash, 'user', 0, 0)
            )
            db.commit()
            app.logger.info(f"User registered: {username}")
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("That username or email is already in use.", "danger")

    return render_template("register.html")

# Tasks Route: Secure
# Display all tasks for logged in user
@app.route("/tasks")
@login_required
def tasks():
    db = get_db()
    tasks = db.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (current_user.id,)
    ).fetchall()

    return render_template("tasks.html", tasks=tasks)

# --- CRUD Functionality ---
# CREATE: Add new task for authenticated user
@app.route("/add_task", methods=["POST"])
@login_required
def add_task():
    title = bleach.clean(request.form["title"])
    description = bleach.clean(request.form["description"])

    if not title:
        flash("Task title cannot be empty.", "warning")
        return redirect(url_for("tasks"))

    db = get_db()
    db.execute(
        "INSERT INTO tasks (user_id, title, description, created_at, updated_at) "
        "VALUES (?, ?, ?, datetime('now'), datetime('now'))",
        (current_user.id, title, description)
    )
    db.commit()

    app.logger.info(f"Task added by {current_user.username}: {title}")

    return redirect(url_for("tasks"))

# EDIT: Allow user to edit existing task belonging to the logged in user
@app.route("/edit/<id>", methods=["GET", "POST"])
@login_required
def edit(id):
    db = get_db()

    if request.method == "POST":
        title = bleach.clean(request.form["title"])
        description = bleach.clean(request.form["description"])

        if not title:
            flash("Task title cannot be empty.", "warning")
            return redirect(url_for("edit", id=id))

        db.execute(
            "UPDATE tasks SET title=?, description=?, updated_at=datetime('now') "
            "WHERE id=? AND user_id=?",
            (title, description, id, current_user.id)
        )
        db.commit()

        app.logger.info(f"Task updated (ID {id}) by {current_user.username}")
        return redirect(url_for("tasks"))

    task = db.execute(
        "SELECT * FROM tasks WHERE id=? AND user_id=?",
        (id, current_user.id)
    ).fetchone()

    if not task:
        app.logger.warning(f"Task not found or unauthorized access attempt on task ID {id} by {current_user.username}")
        return "Task not found or unauthorized.", 404

    return render_template("edit.html", task=task)

# DELETE: Allow user to delete existing task belonging to the logged in user
@app.route("/delete/<id>")
@login_required
def delete(id):
    db = get_db()

    cursor = db.execute(
        "DELETE FROM tasks WHERE id=? AND user_id=?",
        (id, current_user.id)
    )
    db.commit()

    if cursor.rowcount == 0:
        app.logger.warning(f"Unauthorized task deletion attempt on task ID {id} by {current_user.username}")
        return "Not authorized or task doesn't exist.", 403

    app.logger.info(f"Task deleted (ID {id}) by {current_user.username}")

    return redirect(url_for("tasks"))

# --- Administrator ---
@app.route("/adminDash")
@admin_required
def adminDashboard():
    db = get_db()

    all_users = db.execute(
        """
        SELECT ID, username, email, isLocked, failed_login_count, role
        FROM users ORDER BY ID
        """
    ).fetchall()

    recent_logs = get_recent_logs(n=20)

    return render_template("adminDash.html", all_users = all_users, recent_logs = recent_logs)

@app.route("/admin/lock/<int:user_id>")
@admin_required
def admin_lock(user_id):
    if user_id == current_user.id:
        flash("Cannot lock your own account!", "warning")
        return redirect(url_for("adminDashboard"))

    db = get_db()
    db.execute("UPDATE users SET isLocked = 1 WHERE ID = ?", (user_id,))
    db.commit()
    app.logger.warning(f"Admin {current_user.username} locked User ID: {user_id}")
    flash(f"User ID {user_id} has been locked.", "success")
    return redirect(url_for("adminDashboard"))

@app.route("/admin/unlock/<int:user_id>")
@admin_required
def admin_unlock(user_id):
    db = get_db()
    db.execute("UPDATE users SET isLocked = 0, failed_login_count = 0 WHERE ID = ?", (user_id,))
    db.commit()
    app.logger.info(f"Admin {current_user.username} unlocked and reset failed count for User ID: {user_id}")
    flash(f"User ID {user_id} has been unlocked.", "success")
    return redirect(url_for("adminDashboard"))

@app.route("/admin/delete/<int:user_id>")
@admin_required
def admin_delete(user_id):
    if user_id == current_user.id:
        flash("Cannot delete your own account!", "danger")
        return redirect(url_for("adminDashboard"))

    db = get_db()
    cursor = db.execute("DELETE FROM users WHERE ID = ?", (user_id,))
    db.commit()

    if cursor.rowcount > 0:
        app.logger.critical(f"Admin {current_user.username} DELETED user and data (ID: {user_id})")
        flash(f"User ID {user_id} has been permanently deleted.", "info")
    else:
        flash(f"User ID {user_id} not found.", "danger")

    return redirect(url_for("adminDashboard"))

@app.route("/admin/promote/<int:user_id>")
@admin_required
def admin_promote(user_id):
    if user_id == current_user.id:
        flash("You are already an admin!", "warning")
        return redirect(url_for("adminDashboard"))

    db = get_db()

    user_row = db.execute("SELECT role FROM users WHERE ID = ?", (user_id,)).fetchone()
    if user_row and user_row['role'] == 'admin':
        flash(f"User ID {user_id} is already an admin.", "info")
        return redirect(url_for("adminDashboard"))

    db.execute("UPDATE users SET role = 'admin' WHERE ID = ?", (user_id,))
    db.commit()

    app.logger.warning(f"Admin {current_user.username} PROMOTED User ID: {user_id} to 'admin' role.")
    flash(f"User ID {user_id} has been promoted to administrator.", "success")
    return redirect(url_for("adminDashboard"))


# Run Application
if __name__ == "__main__":
    # Use local IP
    app.run(host="127.0.0.1", port=5000, debug=True)