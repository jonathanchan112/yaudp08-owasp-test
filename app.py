from flask import Flask, request, render_template, jsonify, redirect, url_for

app = Flask(__name__)

# In-memory user storage (for demonstration purposes only)
users = {
    'user1': 'password1',
    'user2': 'password2'
}

# Security Misconfiguration: Hardcoded secret key
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Broken Access Control: No authentication required for user data
@app.route('/api/user/<username>')
def get_user(username):
    if username in users:
        return jsonify({'username': username, 'password': users[username]})
    else:
        return jsonify({'error': 'User not found'}), 404

# SQL Injection Simulation (without actual database)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query')
    # Simulate SQL injection by filtering users based on query
    filtered_users = {user: password for user, password in users.items() if query in user}
    return jsonify(filtered_users)

# Cross-Site Scripting (XSS) Vulnerability
@app.route('/xss', methods=['GET'])
def xss():
    script = request.args.get('script')
    return render_template('xss.html', script=script)

# Cross-Site Request Forgery (CSRF) Vulnerability
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    to_user = request.form['to_user']
    # Simulate a transfer without validating the request
    return 'Transfer successful!'

# Sensitive Data Exposure: Exposing user credentials
@app.route('/users')
def users_list():
    return jsonify(users)

# Login form without proper validation
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecurely check credentials
        if username in users and users[username] == password:
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)


