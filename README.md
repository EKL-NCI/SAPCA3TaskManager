**Task Manager**
A secure task management web application built with Flask, providing user authentication, role-based access control, task CRUD operations, and an administrative dashboard with audit logging.

This repository contains two versions of a task management web application built with Flask:

1. Secure Version – Implements best security practices including password hashing, input sanitization, CSRF protection, session security, role-based access control, and logging.

2. Insecure Version – Demonstrates common insecurities such as plaintext passwords, SQL injection vulnerabilities, insecure logging, and missing authentication/authorization.

## Overview

## Overview

| Feature / Version     | Secure Version                     | Insecure Version                     |
|----------------------|----------------------------------|-------------------------------------|
| Password Storage      | Hashed with bcrypt               | Plain text                           |
| SQL Queries           | Parameterized / ORM              | Raw string formatting (SQL injection risk) |
| Input Sanitization    | Yes, using `bleach`             | No                                   |
| CSRF Protection       | Yes, Flask-WTF                  | No                                   |
| Session Management    | Secure cookies, timeout          | None                                 |
| Role-based Access     | Admin vs User                    | None                                 |
| Logging               | Secure with caution              | Logs sensitive info (passwords)     |
| XSS Protection        | Yes                              | No                                   |
| Account Lockouts      | After 5 failed attempts          | None                                 |
| HTTPS / CSP           | Configurable via Flask-Talisman  | None                                 |


Requirements

    Insecure:
    Python 3.10+
    Flask
    Flask-Bootstrap
    SQLite3

    Secure: 
    Flask-Bcrypt
    Flask-Login
    Flask-WTF
    Flask-Talisman
    bleach


**Steps on how to set up the application:**
1. pip install -r requirements.txt
2. python init_db.py
   - Should show Database initialized successfully!
3. Run application with Python app.py
   - App should run on http://127.0.0.1:8080 or http://127.0.0.1:5000
   - Routes available in insecure: /, /register, /login, /tasks, /add_task, /edit/<id>, /delete/<id>
   - Extra routes available in secure: /adminDash