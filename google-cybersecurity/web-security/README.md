# Flask CSRF protection demonstration

This small Flask app demonstrates a synchronizer-token pattern. A same-origin client retrieves a token from /api/csrf-token and sends it in the X-CSRFToken header on state-changing requests. The comparison uses hmac.compare_digest. Session cookies are HttpOnly and SameSite=Lax; Secure cookies are enabled by default.

Set FLASK_SECRET_KEY to a locally generated secret before starting the app, then run csrf_protection.py with Python. For local HTTP development only, use create_app with secure_cookies=False from a development runner. Do not put a production secret in source control. Run the repository tests with python -m unittest discover -s tests -v.

This example is not a complete production security configuration. Add origin checks, HTTPS, secret rotation, rate limiting, input validation, and framework-level security review before adapting it to a real application.
