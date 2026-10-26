import importlib.util
import unittest

from _loader import load_module

if importlib.util.find_spec("flask") is None:
    CREATE_APP = None
else:
    MODULE = load_module("csrf_protection", "google-cybersecurity/web-security/csrf_protection.py")
    CREATE_APP = MODULE.create_app


@unittest.skipIf(CREATE_APP is None, "Install requirements-dev.txt to test the Flask example")
class CsrfProtectionTests(unittest.TestCase):
    def setUp(self):
        self.client = CREATE_APP(secret_key="test-secret", secure_cookies=False).test_client()

    def test_blocks_missing_and_invalid_tokens(self):
        self.assertEqual(self.client.post("/api/transfer-funds", data={"amount": "10"}).status_code, 403)
        self.client.get("/api/csrf-token")
        response = self.client.post(
            "/api/transfer-funds", data={"amount": "10"}, headers={"X-CSRFToken": "invalid"}
        )
        self.assertEqual(response.status_code, 403)

    def test_accepts_token_from_same_session(self):
        token_response = self.client.get("/api/csrf-token")
        token = token_response.get_json()["csrf_token"]
        response = self.client.post(
            "/api/transfer-funds", data={"amount": "10"}, headers={"X-CSRFToken": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
