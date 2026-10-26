"""Small Flask demonstration of synchronizer-token CSRF protection."""

import hmac
import os
import secrets

from flask import Flask, abort, jsonify, request, session


def create_app(secret_key=None, secure_cookies=True):
    key = secret_key or os.environ.get("FLASK_SECRET_KEY")
    if not key:
        raise RuntimeError("Set FLASK_SECRET_KEY before starting the application")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookies,
    )

    @app.get("/api/csrf-token")
    def get_csrf_token():
        token = session.get("_csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        response = jsonify(csrf_token=token)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def csrf_protect():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        token = request.headers.get("X-CSRFToken", "")
        expected = session.get("_csrf_token", "")
        if not token or not expected or not hmac.compare_digest(token, expected):
            abort(403, description="Missing or invalid CSRF token")

    @app.post("/api/transfer-funds")
    def transfer_funds():
        amount = request.form.get("amount", "")
        if not amount:
            abort(400, description="amount is required")
        return jsonify(status="accepted", amount=amount)

    return app


if __name__ == "__main__":
    create_app().run()
