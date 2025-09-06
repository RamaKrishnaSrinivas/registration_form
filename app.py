from flask import Flask, render_template_string, request
import sqlite3,os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask
from flask_talisman import Talisman
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired,DataRequired, Email, Length, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach  # for sanitizing inputs
import re


app = Flask(__name__)


def sanitize_input(data: str) -> str:
    return bleach.clean(data.strip(), strip=True)

# ---- Rate Limiter Setup ----
limiter = Limiter(
    get_remote_address,  # Limit by client IP
    app=app,
    default_limits=["5 per hour"]  # Default limits for all routes
)

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
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
NOTE: <p>1) There is only 5 attempts per day based on email</p>
      <p>2) while typing the password we should correctly entered that.if we didn't there is no way to recover or change the password.</p>
    <br><br><h2>Register</h2>
    <form action="/" method="post">
        <input type="text" name="name" placeholder="Enter your name" required>
        <br>
        <input type="email" name="email" placeholder="Enter your email" required>
        <br>
        <input type="password" name="password" placeholder="Enter your password" required>
        <br>
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
        <br>
        <input type="password" name="password" placeholder="Enter your password" required>
        <br>
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">     
        <button type="submit" name="form_type" value="Login">Login</button>
    </form>
</body>
</html>
"""
dashboard_html="""
<!DOCTYPE html>
<html>
<head>
    <title>welcome</title>
</head>
<html>
<body>
<h1>welcome to my world....</h1>
</html>
</body>
"""

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Limit this route
def combined_route():
    if request.method == 'POST':
        # Check which form was submitted
        form_type = request.form.get('form_type')
        if form_type == 'register':
            # Process the "Registration" form
            name = sanitize_input(request.form['name'])
            email = sanitize_input(request.form['email'])
            password = request.form['password']
            # Inside register:
            if len(password) < 6 or not re.search(r"[0-9]", password) or not re.search(r"[A-Za-z]", password):
                error_message = "Password must be at least 6 characters, include letters and numbers."
                return render_template_string(combined_html, error_message=error_message)

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Save to database
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
            # Process the "Login" form
            email = sanitize_input(request.form['email'])
            password = request.form['password']

            # Check credentials
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            conn.close()

            if user and check_password_hash(user[3], password):  # user[3] is the hashed password
                success_message = f"Welcome back, {user[1]}!"  # user[1] is the name
                return render_template_string(dashboard_html, success_message=success_message)
            else:
                error_message = "Invalid email or password!"
                return render_template_string(combined_html, error_message=error_message)

    # Render the combined form for GET requests
    return render_template_string(combined_html)
    
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
