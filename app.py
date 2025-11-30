from flask import Flask, request, redirect, render_template
from flask_bootstrap import Bootstrap5
import sqlite3
import logging

app = Flask(__name__)

bootstrap = Bootstrap5(app)

# Basic insecure logging
logging.basicConfig(
    filename='insecure_app.log',
    # Debug to capture sensitive info
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Initialize DB
DATABASE = "database.db"

# Database Helper: connects to database and configures rows
def get_db():
    connectDb = sqlite3.connect(DATABASE)
    connectDb.row_factory = sqlite3.Row
    return connectDb

# Flask Routes
# Basic home route
@app.route("/")
def home():
    return render_template("index.html")

# Login Route: Insecure
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Plain text passwords
        username = request.form["username"]
        password = request.form["password"]

        # Logging sensitive user information
        logging.debug(f"Login attempt - username: {username} password: {password}")
        print(f"Login: {username}:{password}")

        # Username and password inserted directly rather than using parameterized queries (Vulnerable to SQL Injection)
        db = get_db()
        user = db.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'").fetchone()

        if user:
            # No sessions or tokens
            return redirect("/tasks")
        else:
            return "Login Failed"

    return render_template("login.html")

# Register Route: Insecure
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Plain text passwords
        username = request.form["username"]
        password = request.form["password"]

        # Logging sensitive user information
        logging.debug(f"Register attempt - username: {username} password: {password}")
        print(f"Register: {username}:{password}")

        # Vulnerable to SQL Injection
        db = get_db()
        db.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        db.commit()

        return redirect("/login")
    return render_template("register.html")

# Tasks Route: Insecure
@app.route("/tasks")
def tasks():
    db = get_db()
    # Sensitive data exposure vulnerability: any user can see all tasks, no authentication
    tasks = db.execute("SELECT * FROM tasks").fetchall()
    return render_template("tasks.html", tasks=tasks)

# CRUD Functionality
# CREATE: Add new task
@app.route("/add_task", methods=["POST"])
def add_task():
    # No validation on inputs
    title = request.form["title"]
    description  = request.form["description"]

    # Vulnerable to SQL Injection
    db = get_db()
    db.execute(f"INSERT INTO tasks (title, description) VALUES ('{title}', '{description}')")
    db.commit()

    return redirect("/tasks")

# EDIT: Allow user to edit existing task
@app.route("/edit/<id>", methods=["GET", "POST"])
def edit(id):
    db = get_db()

    if request.method == "POST":
        # No validation on inputs
        new_title = request.form["title"]
        new_desc = request.form["description"]

        # Vulnerable to SQL Injection
        db.execute(f"UPDATE tasks SET title='{new_title}', description='{new_desc}' WHERE id={id}")
        db.commit()

        return redirect("/tasks")

    task = db.execute(f"SELECT * FROM tasks WHERE id={id}").fetchone()
    return render_template("edit.html", task=task)

# DELETE: Allow user to delete existing task
@app.route("/delete/<id>")
def delete(id):
    db = get_db()

    # Vulnerable to SQL Injection
    db.execute(f"DELETE FROM tasks WHERE id={id}")
    db.commit()

    return redirect("/tasks")


if __name__ == "__main__":
    # Use local IP
    app.run(host="127.0.0.1", port=5000, debug=True)