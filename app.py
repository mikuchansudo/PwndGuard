import flask
from flask import Flask, request, render_template
import re
import hashlib
import requests
import secrets
import string

app = Flask(__name__)

# Check password strength
def check_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    score = 0
    feedback = []

    if length >= 12: score += 2
    elif length >= 8: score += 1
    else: feedback.append("Too short (min 8, 12+ best).")
    if has_upper: score += 1
    else: feedback.append("Add uppercase.")
    if has_lower: score += 1
    else: feedback.append("Add lowercase.")
    if has_digit: score += 1
    else: feedback.append("Add numbers.")
    if has_special: score += 1
    else: feedback.append("Add special chars (e.g., !@#$).")

    strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
    return strength, feedback

# Check if password was breached (HIBP API)
def check_breached_password(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for h in hashes:
            if suffix in h:
                count = int(h.split(':')[1])
                return True, count
    return False, 0

# Generate a strong password
def generate_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(16))

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    suggestion = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password:
            strength, feedback = check_password_strength(password)
            breached, breach_count = check_breached_password(password)
            breach_msg = f"Found in {breach_count} breaches!" if breached else "No breaches found."
            result = {'strength': strength, 'feedback': feedback, 'breached': breached, 'breach_msg': breach_msg}
            if strength != "Strong" or breached:
                suggestion = generate_password()
    return render_template('index.html', result=result, suggestion=suggestion)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
