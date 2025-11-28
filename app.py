from flask import Flask, request, redirect, render_template
from flask_bootstrap import Bootstrap5
import sqlite3
import logging

app = Flask(__name__)

bootstrap = Bootstrap5(app)

logging.basicConfig(
    filename='insecure_app.log',
    # Debug to capture sensitive info
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

DATABASE = "database.db"

# Database helper
def get_db():
    connectDb = sqlite3.connect(DATABASE)
    connectDb.row_factory = sqlite3.Row
    return connectDb

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Plain text passwords
        username = request.form["username"]
        password = request.form["password"]

        logging.debug(f"Login attempt - username: {username} password: {password}")
        print(f"Login: {username}:{password}")

        db = get_db()

        user = db.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'").fetchone()

        if user:
            return redirect("/tasks")
        else:
            return "Login Failed"

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Plain text passwords
        username = request.form["username"]
        password = request.form["password"]

        logging.debug(f"Register attempt - username: {username} password: {password}")
        print(f"Register: {username}:{password}")

        db = get_db()

        # Vulnerable to SQL Injection
        db.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        db.commit()

        return redirect("/login")
    return render_template("register.html")

@app.route("/tasks")
def tasks():
    db = get_db()
    tasks = db.execute("SELECT * FROM tasks").fetchall()
    return render_template("tasks.html", tasks=tasks)

# CRUD Functionality
@app.route("/add_task", methods=["POST"])
def add_task():
    title = request.form["title"]
    description  = request.form["description"]

    db = get_db()

    # Vulnerable to SQL Injection
    db.execute(f"INSERT INTO tasks (title, description) VALUES ('{title}', '{description}')")
    db.commit()

    return redirect("/tasks")

@app.route("/edit/<id>", methods=["GET", "POST"])
def edit(id):
    db = get_db()

    if request.method == "POST":
        new_title = request.form["title"]
        new_desc = request.form["description"]

        # Vulnerable to SQL Injection
        db.execute(f"UPDATE tasks SET title='{new_title}', description='{new_desc}' WHERE id={id}")
        db.commit()

        return redirect("/tasks")

    task = db.execute(f"SELECT * FROM tasks WHERE id={id}").fetchone()
    return render_template("edit.html", task=task)

@app.route("/delete/<id>")
def delete(id):
    db = get_db()

    # Vulnerable to SQL Injection
    db.execute(f"DELETE FROM tasks WHERE id={id}")
    db.commit()

    return redirect("/tasks")


if __name__ == "__main__":
    app.run(debug=True)