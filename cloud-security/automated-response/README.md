# Project: Automated Incident Response (SOAR Engine)

## 📋 Project Overview
This project presents an automated Incident Response pipeline using Python. It simulates real-time containment actions—such as network host quarantine and IAM session revocation—driven by high-severity AWS GuardDuty alerts.

## 🛠️ STAR Analysis
* **Situation:** Manual incident response workflows take an average of 30+ minutes from alert generation to containment, leaving a wide window for data exfiltration.
* **Task:** Build an automated response function that parses threat alerts and instantly executes containment policies against affected cloud resources.
* **Action:** Authored a Python automation handler designed to evaluate GuardDuty JSON event payloads. Programmed conditional logic that automatically isolates compromised EC2 instances behind a quarantine Security Group and applies inline `DenyAll` policies to compromised IAM identities.
* **Result:** Reduced containment response time from minutes to milliseconds, eliminating human delay during critical off-hours incidents.