from flask import Flask, request, render_template, jsonify
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure_secret_key'  # Security Misconfiguration

# Database setup
conn = sqlite3.connect('example.db')
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
conn.commit()
conn.close()

# SQL Injection Vulnerability
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return 'Login successful'
    else:
        return 'Login failed'

# Cross-Site Scripting (XSS) Vulnerability
@app.route('/xss')
def xss():
    user_input = request.args.get('input')
    return render_template('xss.html', input=user_input)

# xss.html template with autoescape disabled
# {% autoescape false %}
# <p>User Input: {{ input }}</p>
# {% endautoescape %}

# Cross-Site Request Forgery (CSRF) Vulnerability
@app.route('/csrf', methods=['POST'])
def csrf():
    # No CSRF protection
    return 'Action performed'

# Broken Access Control
@app.route('/admin')
def admin():
    # No access control
    return 'Welcome, Admin!'

# Security Misconfiguration (Debug Mode Enabled)
if __name__ == '__main__':
    app.run(debug=True)
