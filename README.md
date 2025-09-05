# Flask Authentication App with Email Rate Limiting

This is a Flask web application that provides **Register** and **Login** functionality with:
- CSRF protection using Flask-WTF
- Secure password hashing using Werkzeug
- Flask-Talisman for security headers
- Flask-Limiter for **email-based rate limiting** (prevents brute-force login)
- SQLite as the database

## Features
- User registration (with hashed passwords)
- User login
- Rate limiting by email (e.g., 3 attempts per day)
- Basic security best practices enabled

## Tech Stack
- **Backend**: Flask (Python)
- **Database**: SQLite (lightweight, file-based)
- **Security**: Flask-WTF, CSRF, Werkzeug, Talisman
- **Rate Limiting**: Flask-Limiter

## Run Locally
1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/registration_form.git
   cd registration_form
