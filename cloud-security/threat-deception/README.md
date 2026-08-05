# Project: Cloud Deception & Honeytoken Architecture

## 📋 Project Overview
This module demonstrates threat deception techniques by deploying a decoy S3 bucket ("Canary Bucket") paired with AWS EventBridge rules. The asset acts as a honeypot; any attempt to read the file triggers an immediate high-severity security alert.

## 🛠️ STAR Analysis
* **Situation:** Attackers who breach a perimeter often perform internal reconnaissance to look for credential files (`passwords.csv`, `keys.pem`).
* **Task:** Implement an early-warning intrusion detection mechanism that alerts security teams when an unauthorized entity probes decoy assets.
* **Action:** Authored Terraform IaC deploying a decoy S3 bucket (`corp-confidential-passwords-canary`) containing dummy credentials. Attached CloudWatch EventBridge rules to intercept `GetObject` API calls.
* **Result:** Created an alert signal with near-zero false-positive rates, giving SOC operations immediate visibility into active lateral movement.
