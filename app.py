import flask
from flask import Flask, request, render_template
import re
import hashlib
import requests
import secrets
import string
import math

app = Flask(__name__)

def check_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    score = 0
    feedback = []
    details = {}

    details['length'] = length
    if length >= 12:
        score += 2
        feedback.append("Length: Excellent (12+ chars)")
    elif length >= 8:
        score += 1
        feedback.append("Length: Good (8-11 chars)")
    else:
        feedback.append("Length: Too short (<8 chars)")

    details['uppercase'] = has_upper
    if has_upper:
        score += 1
        feedback.append("Uppercase: Yes")
    else:
        feedback.append("Uppercase: Missing")
    
    details['lowercase'] = has_lower
    if has_lower:
        score += 1
        feedback.append("Lowercase: Yes")
    else:
        feedback.append("Lowercase: Missing")
    
    details['digits'] = has_digit
    if has_digit:
        score += 1
        feedback.append("Digits: Yes")
    else:
        feedback.append("Digits: Missing")
    
    details['special'] = has_special
    if has_special:
        score += 1
        feedback.append("Special: Yes")
    else:
        feedback.append("Special: Missing")

    # Entropy calculation
    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_special: pool += 32
    entropy = length * math.log2(pool) if pool > 0 else 0
    details['entropy'] = round(entropy, 2)

    # Crack time estimate (10 billion guesses/second)
    guesses_per_second = 10_000_000_000
    seconds_to_crack = (2 ** entropy) / guesses_per_second if entropy > 0 else 0
    details['crack_time'] = format_crack_time(seconds_to_crack)

    strength = "Weak" if score < 3 else "Moderate" if score < 5 else "Strong"
    details['score'] = score
    return strength, feedback, details

def format_crack_time(seconds):
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''}"
    elif seconds < 31536000:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''}"
    else:
        years = int(seconds / 31536000)
        if years > 1000000:
            return "Millions of years"
        return f"{years} year{'s' if years != 1 else ''}"

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
            strength, feedback, details = check_password_strength(password)
            breached, breach_count = check_breached_password(password)
            breach_msg = f"Found in {breach_count} breaches!" if breached else "No breaches found."
            result = {
                'strength': strength,
                'feedback': feedback,
                'details': details,
                'breached': breached,
                'breach_msg': breach_msg
            }
            if strength != "Strong" or breached:
                suggestion = generate_password()
    return render_template('index.html', result=result, suggestion=suggestion)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
