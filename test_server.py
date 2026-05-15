#!/usr/bin/env python3
"""
Test Server with User Enumeration Vulnerabilities
This server intentionally demonstrates various user enumeration techniques
"""

from flask import Flask, request, jsonify
import time

app = Flask(__name__)

# Simulated database of valid users
VALID_USERS = {'admin', 'john', 'sarah', 'user', 'test', 'support'}
VALID_EMAILS = {'admin@example.com', 'john@example.com', 'support@example.com'}


@app.route('/')
def index():
    return """
    <h1>GuessWho Test Server</h1>
    <p>This server has intentional user enumeration vulnerabilities for testing.</p>
    <h2>Vulnerable Endpoints:</h2>
    <ul>
        <li><b>POST /login</b> - Status code enumeration (valid users get 401, invalid get 404)</li>
        <li><b>POST /login-timing</b> - Timing-based enumeration</li>
        <li><b>POST /forgot-password</b> - Message-based enumeration</li>
        <li><b>POST /register</b> - Length-based enumeration</li>
        <li><b>GET /api/user/&lt;username&gt;</b> - REST API enumeration</li>
    </ul>
    <h2>Test Commands:</h2>
    <pre>
# Test login endpoint (status code difference)
python guesswho.py -u "http://localhost:8080/login" -w wordlists/usernames.txt -d "username=FUZZ&password=test"

# Test timing-based endpoint
python guesswho.py -u "http://localhost:8080/login-timing" -w wordlists/usernames.txt -d "username=FUZZ&password=test"

# Test forgot password (message difference)
python guesswho.py -u "http://localhost:8080/forgot-password" -w wordlists/emails.txt -d "email=FUZZ"

# Test registration (length difference)
python guesswho.py -u "http://localhost:8080/register" -w wordlists/usernames.txt -d "username=FUZZ"

# Test REST API (GET request)
python guesswho.py -u "http://localhost:8080/api/user/FUZZ" -w wordlists/usernames.txt -X GET
    </pre>
    """


@app.route('/login', methods=['POST'])
def login_status_code():
    """
    Vulnerability: Different status codes for valid vs invalid users
    - Valid user: 401 Unauthorized
    - Invalid user: 404 Not Found
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if username in VALID_USERS:
        # User exists but wrong password
        return jsonify({'error': 'Invalid credentials'}), 401
    else:
        # User doesn't exist
        return jsonify({'error': 'User not found'}), 404


@app.route('/login-timing', methods=['POST'])
def login_timing():
    """
    Vulnerability: Timing difference for valid vs invalid users
    - Valid user: Slower (simulates password hash checking)
    - Invalid user: Fast response
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if username in VALID_USERS:
        # Simulate password hash verification delay
        time.sleep(0.2)
        return jsonify({'error': 'Invalid password'}), 401
    else:
        # No delay for invalid users
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """
    Vulnerability: Different messages for valid vs invalid emails
    - Valid email: "Password reset link sent"
    - Invalid email: "Email not found"
    """
    email = request.form.get('email', '')
    
    if email in VALID_EMAILS:
        return jsonify({
            'success': True,
            'message': 'Password reset link has been sent to your email. Please check your inbox.'
        }), 200
    else:
        return jsonify({
            'success': False,
            'message': 'Email address not found in our system.'
        }), 404


@app.route('/register', methods=['POST'])
def register():
    """
    Vulnerability: Different response lengths for existing vs new users
    - Existing user: Longer error message
    - New user: Short success message
    """
    username = request.form.get('username', '')
    
    if username in VALID_USERS:
        # Long error message for existing users
        return jsonify({
            'error': 'Username already taken. This username is already registered in our system. '
                    'Please choose a different username or try logging in if this is your account. '
                    'If you forgot your password, you can reset it using the forgot password link.'
        }), 400
    else:
        # Short message for new users
        return jsonify({'success': True}), 200


@app.route('/api/user/<username>', methods=['GET'])
def api_user(username):
    """
    Vulnerability: REST API returns different status for existing users
    - Valid user: 200 OK with user data
    - Invalid user: 404 Not Found
    """
    if username in VALID_USERS:
        return jsonify({
            'username': username,
            'exists': True,
            'profile': 'public'
        }), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@app.route('/secure-login', methods=['POST'])
def secure_login():
    """
    NOT Vulnerable: Proper implementation (same response for all cases)
    This is how it SHOULD be done
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Always return the same generic message
    # Same status code, same timing, same response
    time.sleep(0.1)  # Consistent delay
    return jsonify({'error': 'Invalid username or password'}), 401


if __name__ == '__main__':
    print("=" * 70)
    print("GuessWho Test Server")
    print("=" * 70)
    print("\nValid test users:", ", ".join(VALID_USERS))
    print("Valid test emails:", ", ".join(VALID_EMAILS))
    print("\nServer starting on http://localhost:8080")
    print("\nOpen http://localhost:8080 in your browser for test commands")
    print("=" * 70)
    print()
    
    app.run(host='0.0.0.0', port=8080, debug=False)
