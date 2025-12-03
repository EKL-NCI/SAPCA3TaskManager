import logging
import sqlite3
import os
import bleach

from logging.handlers import RotatingFileHandler
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_talisman import Talisman
from flask_bootstrap import Bootstrap5

app = Flask(__name__)
bootstrap = Bootstrap5(app)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'your_secret_key'

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

DATABASE = "secure_db.db"
Talisman(app, content_security_policy=None)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# Database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

if not os.path.exists("logs"):
    os.makedirs("logs")

# Logging
file_handler = RotatingFileHandler(
    "logs/app.log", maxBytes=2_000_000, backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# User class for flask-login
class User(UserMixin):
    def __init__(self, id_, username, email):
        self.id = id_
        self.username = username
        self.email = email


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT ID, username, email FROM users WHERE ID = ?",(user_id,)).fetchone()

    if row:
        return User(row["ID"], row["username"], row["email"])
    return None

# Flask Routes
# Basic home route
@app.route("/")
def home():
    return render_template("index.html")

# Login Route: Secure
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Plain text passwords
        identifier = request.form["username_or_email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT ID, username, email, pass_hash FROM users ""WHERE username = ? OR email = ?",(identifier, identifier)).fetchone()

        if user and bcrypt.check_password_hash(user["pass_hash"], password):
            user_obj = User(user["ID"], user["username"], user["email"])
            login_user(user_obj)

            app.logger.info(f"Successful login: {user['username']}")
            return redirect(url_for("tasks"))
        else:
            app.logger.warning(f"Failed login: {identifier}")
            flash("Invalid login credentials", "danger")

    return render_template("login.html")

# Logout Route
@app.route("/logout")
def logout():
    app.logger.info(f"Logged out: {current_user.username}")
    logout_user()
    return redirect('/')

# Register Route: Secure
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        pass_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, pass_hash, role) "
                "VALUES (?, ?, ?, 'user')",
                (username, email, pass_hash)
            )
            db.commit()
            app.logger.info(f"User registered: {username}")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("That username or email is already in use.", "danger")

    return render_template("register.html")

# Tasks Route: Secure
@app.route("/tasks")
@login_required
def tasks():
    db = get_db()
    tasks = db.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (current_user.id,)
    ).fetchall()

    return render_template("tasks.html", tasks=tasks)


# CRUD Functionality
# CREATE: Add new task
@app.route("/add_task", methods=["POST"])
@login_required
def add_task():
    title = bleach.clean(request.form["title"])
    description = bleach.clean(request.form["description"])

    db = get_db()
    db.execute(
        "INSERT INTO tasks (user_id, title, description, created_at, updated_at) "
        "VALUES (?, ?, ?, datetime('now'), datetime('now'))",
        (current_user.id, title, description)
    )
    db.commit()

    app.logger.info(f"Task added by {current_user.username}: {title}")

    return redirect(url_for("tasks"))

# EDIT: Allow user to edit existing task
@app.route("/edit/<id>", methods=["GET", "POST"])
@login_required
def edit(id):
    db = get_db()

    if request.method == "POST":
        title = bleach.clean(request.form["title"])
        description = bleach.clean(request.form["description"])

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
        return "Task not found or unauthorized.", 404

    return render_template("edit.html", task=task)

# DELETE: Allow user to delete existing task
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
        return "Not authorized or task doesn't exist.", 403

    app.logger.info(f"Task deleted (ID {id}) by {current_user.username}")

    return redirect(url_for("tasks"))

# Run Application
if __name__ == "__main__":
    # Use local IP
    app.run(host="127.0.0.1", port=5000, debug=True)