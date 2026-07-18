# Web Application Security: CSRF Mitigation

## 📋 Project Overview
This project demonstrates the cryptographic implementation of Cross-Site Request Forgery (CSRF) protections within a Python backend, ensuring state-changing operations are strictly authenticated.

## 🛠️ STAR Analysis
* **Situation:** Attackers leverage authenticated user sessions to trick browsers into executing malicious state-changing requests (e.g., fund transfers) without the user's knowledge.
* **Task:** Implement a defense mechanism that forces the client to prove the request was intentionally initiated from the legitimate frontend interface.
* **Action:** Built a Python application that generates a unique, cryptographically secure string (`os.urandom`) upon session creation. The application is configured to require this token to be transmitted back via a custom HTTP header (`X-CSRFToken`) for all `POST`/`PUT` requests. Validation utilizes `hmac.compare_digest` to mitigate timing attack vulnerabilities.
* **Result:** Effectively neutralized CSRF vectors by decoupling authentication (cookies) from authorization (the anti-CSRF token).