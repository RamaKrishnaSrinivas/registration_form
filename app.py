from flask import Flask, render_template_string, request
import sqlite3,os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask
from flask_talisman import Talisman
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired,DataRequired, Email, Length, Regexp
import bleach  # for sanitizing inputs
import re
import time


app = Flask(__name__)


def sanitize_input(data: str) -> str:
    return bleach.clean(data.strip(), strip=True)


# ---- Security Config ----
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-prod")

# ---- Enable CSRF ----
csrf = CSRFProtect(app)

# Enforce HTTPS
Talisman(app)

combined_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Registration_form</title>
</head>
<body style="text-align: center; align-items:center; align-content-center; padding:500px; margin-top: 100px; background:orange; padding-top: 20px;">
    <h2>Register</h2>
    <form action="/" method="post">
        <input type="text" name="name" placeholder="Enter your name" required>
        <br><br>
        <input type="email" name="email" placeholder="Enter your email" required>
        <br><br>
        <input type="password" name="password" placeholder="Enter your password" required>
        <br><br>
    <!-- CSRF token here -->
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
           <button type="submit" name="form_type" value="register">Register</button>
    </form>

    {% if success_message is defined %}
        <h3 style="color: green;">{{ success_message }}</h3>
    {% endif %}

    {% if error_message is defined %}
        <h3 style="color: red;">{{ error_message }}</h3>
    {% endif %}
    <hr>

    <p>or</p>
    
    <h2>Login</h2>
    <form action="/" method="post">
        <input type="email" name="email" placeholder="Enter your email" required>
        <br><br>
        <input type="password" name="password" placeholder="Enter your password" required>
    <br><br>
    <!-- CSRF token here too -->
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">     
   <button type="submit" name="form_type" value="Login">Login</button>
    </form>
</body>
</html>
"""
dashboard_html="""
<!Doctype_html>
<html>
<head>
<title>Dashboard</title>
</head>
<body>
<h2> Welcome to my world....</h2>
<h1>your rkso....</h1>
</body>
</html>
"""

MAX_ATTEMPTS = 3
BLOCK_TIME = 86400 #seconds

def init_attempts_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS attempts (
            email TEXT PRIMARY KEY,
            count INTEGER,
            last_attempt REAL
        )
    ''')
    conn.commit()
    conn.close()

init_attempts_db()

def check_attempt(email):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT count, last_attempt FROM attempts WHERE email=?", (email,))
    row = c.fetchone()

    if row:
        count, last_attempt = row
        if count >= MAX_ATTEMPTS and time.time() - last_attempt < BLOCK_TIME:
            conn.close()
            return False  # blocked
        elif time.time() - last_attempt >= BLOCK_TIME:
            # reset after block time
            c.execute("UPDATE attempts SET count=1, last_attempt=? WHERE email=?", (time.time(), email))
        else:
            c.execute("UPDATE attempts SET count=count+1, last_attempt=? WHERE email=?", (time.time(), email))
    else:
        c.execute("INSERT INTO attempts (email, count, last_attempt) VALUES (?, ?, ?)", (email, 1, time.time()))

    conn.commit()
    conn.close()
    return True


@app.route('/', methods=['GET', 'POST'])
def combined_route():
    if request.method == 'POST':
        # Check which form was submitted
        form_type = request.form.get('form_type')

        if form_type == 'register':
            # Process the "Registration" form
            name = sanitize_input(request.form['name'])
            email = sanitize_input(request.form['email'])
            password = request.form['password']

            # Password validation
            if len(password) < 6 or not re.search(r"[0-9]", password) or not re.search(r"[A-Za-z]", password):
                error_message = "Password must be at least 6 characters, include letters and numbers."
                return render_template_string(combined_html, error_message=error_message)

            hashed_password = generate_password_hash(password)

            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL
                )
            ''')

            # Check if email already exists
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            if c.fetchone():
                conn.close()
                error_message = "Email already registered!"
                return render_template_string(combined_html, error_message=error_message)

            # Insert new user
            c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
            conn.commit()
            conn.close()

            success_message = f"User {name} registered successfully with email {email}."
            return render_template_string(combined_html, success_message=success_message)

        elif form_type == 'Login':
            email = sanitize_input(request.form['email'])
            password = request.form['password']

            # ✅ Check rate limiting before validating credentials
            if not check_attempt(email):
                error_message = "Too many failed attempts. Try again later!"
                return render_template_string(combined_html, error_message=error_message)

            # Check credentials
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            conn.close()

            if user and check_password_hash(user[3], password):
                # ✅ Reset attempts on successful login
                conn = sqlite3.connect('users.db')
                c = conn.cursor()
                c.execute("DELETE FROM attempts WHERE email=?", (email,))
                conn.commit()
                conn.close()

                success_message = f"Welcome back, {user[1]}!"
                return render_template_string(dashboard_html, success_message=success_message)
            else:
                error_message = "Invalid email or password!"
                return render_template_string(combined_html, error_message=error_message)

    # ✅ Default GET request → show the form
    return render_template_string(combined_html)

if __name__ == "__main__":
    app.run(debug=True,ssl_context="adhoc")  # Creates a temporary HTTPS certificate
