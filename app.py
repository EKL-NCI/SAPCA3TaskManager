import logging
import sqlite3

from flask import Flask, render_template, request, redirect, session
from flask_bootstrap import Bootstrap5
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

bootstrap = Bootstrap5(app)
bcrypt = Bcrypt(app)
DATABASE = "secure_db.db"

def get_db():
    connectDb = sqlite3.connect(DATABASE)
    connectDb.row_factory = sqlite3.Row
    return connectDb

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
        user = db.execute(
            """
            SELECT ID, pass_hash FROM users 
            WHERE username = ? OR email = ?
            """,
            (identifier, identifier)
        ).fetchone()

        if user and bcrypt.check_password_hash(user['pass_hash'], password):
            session['user_id'] = user['ID']
            logging.info(f"User logged in: {identifier}")
            return redirect("/tasks")
        else:
            logging.warning(f"Failed login attempt for username: {identifier}")
            return "Login Failed"

    return render_template("login.html")

# Logout Route
@app.route("/logout")
def logout():
    session.pop('user_id', None)
    return redirect('/')

# Register Route: Secure
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        pass_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        logging.info(f"Register attempt for user: {username}")

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, email, pass_hash, role) VALUES (?, ?, ?, 'user')",
                       (username, email, pass_hash))
            db.commit()
            return redirect("/login")

        except sqlite3.IntegrityError:
            error_msg = "Registration failed: Username or Email already in use. Please choose a different one."
            return render_template("register.html", error_message=error_msg), 400

    return render_template("register.html", error_message=None)

# Tasks Route: Secure
@app.route("/tasks")
def tasks():
    user_id = session['user_id']
    db = get_db()
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()

    if user_id is None:
        return "User not found or unauthorized", 404
    return render_template("tasks.html", tasks=tasks)

# CRUD Functionality
# CREATE: Add new task
@app.route("/add_task", methods=["POST"])
def add_task():
    user_id = session['user_id']
    title = request.form["title"]
    description  = request.form["description"]

    db = get_db()
    db.execute("INSERT INTO tasks (user_id, title, description, created_at, updated_at) VALUES (?, ?, ?, datetime('now'), datetime('now'))",(user_id, title, description))
    db.commit()

    return redirect("/tasks")

# EDIT: Allow user to edit existing task
@app.route("/edit/<id>", methods=["GET", "POST"])
def edit(id):
    user_id = session['user_id']
    db = get_db()

    if request.method == "POST":
        new_title = request.form["title"]
        new_desc = request.form["description"]

        db.execute("UPDATE tasks SET title=?, description=?, updated_at=datetime('now') WHERE id=? AND user_id=?",(new_title, new_desc, id, user_id))
        db.commit()

        return redirect("/tasks")

    task = db.execute("SELECT * FROM tasks WHERE id=? AND user_id=?", (id, user_id)).fetchone()
    if task is None:
        return "Task not found or unauthorized", 404

    return render_template("edit.html", task=task)

# DELETE: Allow user to delete existing task
@app.route("/delete/<id>")
def delete(id):
    user_id = session['user_id']
    db = get_db()

    cursor = db.execute("DELETE FROM tasks WHERE id=? AND user_id=?",(id, user_id))
    db.commit()

    if cursor.rowcount == 0:
        return "Task not found or unauthorized to delete.", 403

    return redirect("/tasks")


if __name__ == "__main__":
    # Use local IP
    app.run(host="127.0.0.1", port=5000, debug=True)