from flask import Flask, request, render_template_string, redirect, session, make_response
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "weaksecret"  # A6:2017 - Security Misconfiguration (weak secret)

# SQLite setup (No proper sanitization or prepared statements)
def init_db():
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments 
                 (id INTEGER PRIMARY KEY, content TEXT)''')
    conn.commit()
    conn.close()

# A1:2021 - Broken Access Control
@app.route('/admin')
def admin():
    # No proper authentication check
    if 'username' in session:
        return "Admin Panel: All user data here!"
    return "Not logged in!"

# A2:2021 - Cryptographic Failures
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # Stored in plaintext
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        # A3:2021 - Injection (SQL Injection)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect('/')
        return "Login failed"
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="text" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# A3:2021 - Injection (XSS via comments)
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        content = request.form['content']
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        c.execute("INSERT INTO comments (content) VALUES (?)", (content,))
        conn.commit()
        conn.close()
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()
    c.execute("SELECT content FROM comments")
    comments = c.fetchall()
    conn.close()
    # No escaping/output encoding - XSS vulnerability
    comments_html = ''.join([f'<p>{comment[0]}</p>' for comment in comments])
    return f'''
        <form method="post">
            Comment: <input type="text" name="content">
            <input type="submit" value="Post">
        </form>
        <div>{comments_html}</div>
    '''

# A4:2021 - Insecure Design (No rate limiting, weak password policy)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # No complexity check
        conn = sqlite3.connect('vulnerable.db')
        c = conn.cursor()
        c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()
        conn.close()
        return "Registered!"
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="text" name="password"><br>
            <input type="submit" value="Register">
        </form>
    '''

# A5:2021 - Security Misconfiguration
@app.route('/debug')
def debug():
    return str(app.config)  # Exposes configuration details

# A7:2021 - Identification and Authentication Failures
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')  # No session invalidation

# A8:2021 - Software and Data Integrity Failures
@app.route('/update')
def update():
    # Simulates insecure deserialization or unvalidated update
    os.system(request.args.get('cmd', ''))  # Command injection
    return "Update executed"

# A9:2021 - Security Logging and Monitoring Failures
@app.route('/error')
def error():
    try:
        raise Exception("Test error")
    except:
        # No logging implemented
        return "Something went wrong"

# A10:2021 - Server-Side Request Forgery (SSRF)
@app.route('/fetch')
def fetch():
    import requests
    url = request.args.get('url', '')
    response = requests.get(url)  # No validation on URL
    return response.text

@app.route('/')
def index():
    return "Welcome to Vulnerable App!"

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0')  # Debug mode on, exposed to all interfaces

