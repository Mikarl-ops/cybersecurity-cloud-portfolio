"""
Filename: csrf_protection.py
Description: A demonstration of generating, transmitting, and validating secure 
             CSRF tokens in a web application using Python and Flask to prevent 
             state-changing attacks.
"""

from flask import Flask, request, session, abort
import os
import hmac

app = Flask(__name__)
# In production, this secret key must be stored in an environment variable
app.secret_key = os.urandom(24)

def generate_csrf_token():
    """Generates a cryptographically secure token and stores it in the user's session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(24).hex()
    return session['_csrf_token']

@app.before_request
def csrf_protect():
    """Intercepts incoming state-changing requests to validate the token transmission."""
    if request.method in ["POST", "PUT", "DELETE"]:
        # Extract the token transmitted via the custom HTTP header
        token = request.headers.get('X-CSRFToken')
        if not token:
            abort(403, description="CSRF token missing from request headers.")
            
        # Use hmac.compare_digest to prevent timing attacks during validation
        if not hmac.compare_digest(token, session.get('_csrf_token', '')):
            abort(403, description="Invalid CSRF token detected.")

@app.route("/api/transfer-funds", methods=["POST"])
def transfer_funds():
    """A simulated sensitive endpoint protected by the before_request token check."""
    amount = request.form.get("amount")
    return f"Success: Securely transferred ${amount}. Request authenticated."

if __name__ == "__main__":
    print("[*] Starting secure web application with CSRF protection enabled...")
    # Generate a dummy token to show how it would be injected into the front-end
    with app.test_request_context():
        session['_csrf_token'] = os.urandom(24).hex()
        print(f"[+] Example token transmitted to client: {session['_csrf_token']}")