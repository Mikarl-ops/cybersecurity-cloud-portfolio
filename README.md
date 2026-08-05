# 🔒 Cybersecurity & Cloud Security Engineering Portfolio

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-1.0+-844FBA?style=for-the-badge&logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cloud-232F3E?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Google Cloud](https://img.shields.io/badge/GCP-Security-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-Packet_Analysis-167DA4?style=for-the-badge&logo=wireshark&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/DevSecOps-CI%2FCD-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

Welcome to my centralized security portfolio. This repository houses technical implementations, automated scripts, cloud infrastructure blueprints, and incident response write-ups covering both **Google Cybersecurity** and **Cloud Security** pathways.

---

## 🏅 Certifications & Pathways
* **Google Cybersecurity Professional Certificate** 
* **Cloud Security Certification** (AWS / Google Cloud / Azure)

---

## 🛠️ Technical Skill Matrix

| Category | Core Competencies & Technologies |
| :--- | :--- |
| **Security Automation** | Python (`re`, `hmac`, `requests`), Bash Scripting, `iptables` Remediation |
| **Log & Forensics Audit** | SQL (Data Analysis & Join Queries), Wireshark (`.pcap` Filtering), Network PCAP Analysis |
| **Cloud Security (AWS/GCP)** | IAM Least-Privilege Design, S3 Bucket Hardening, TLS In-Transit Enforcement |
| **Infrastructure as Code** | Terraform (Secure VPC Provisioning, Stateful Firewall Rules) |
| **Application & AI Security** | Anti-CSRF Cryptographic Mitigation, FGSM Adversarial AI Threat Modeling |
| **DevSecOps Pipeline** | GitHub Actions, SAST Scanning (Bandit for Python, Checkov for IaC) |

---

## 📂 Repository Directory Map & Featured Projects

### 🐍 1. Python Security Automation
* [`📂 Allow List Updater`](./google-cybersecurity/python-automation/) — Automated parser that strips revoked IP permissions from access control files.
* [`📂 Brute-Force Log Detector`](./google-cybersecurity/python-automation/brute_force_detector/) — Regex log parser isolating failed auth attempts and flagging threshold breaches.
* [`📂 Active Threat Remediation`](./google-cybersecurity/python-automation/active_threat_mitigation/) — Script that dynamically generates executable Linux `iptables` drop rules from threat feeds.
* [`📂 Threat Intelligence API Automation`](./google-cybersecurity/python-automation/cve_threat_intel.py) — NVD REST API Vulnerability Ingestion Engine.
* [`📂 Automated SOAR Response Engine`](./cloud-security/automated-response/) — Incident response handler simulating host isolation and IAM credential revocation upon GuardDuty alerts.

### 🔍 2. Security Operations, SQL & Network Forensics
* [`📂 Linux System Hardening Audit`](./google-cybersecurity/system-security/) — Bash audit script checking SSH config hardening, open listening ports, and world-writable files.
* [`📂 Forensic SQL Queries`](./google-cybersecurity/linux-sql/) — Relational queries used to investigate after-hours unauthorized logins and insider threat activity.
* [`📂 SQL Privilege Escalation Audit`](./google-cybersecurity/linux-sql/privilege_escalation_audit.sql) — Audit scripts hunting for unauthorized role changes and orphaned terminated employee accounts.
* [`📂 Wireshark Network Packet Analysis`](./google-cybersecurity/network-security/) — Technical walkthrough isolating a TCP SYN flood attack and unencrypted HTTP POST basic auth payloads.
* [`📂 DNS Tunneling & Exfiltration Analysis`](./google-cybersecurity/network-security/DNS_EXFILTRATION_README.md) — Case study analyzing Base64 data exfiltration hidden inside UDP Port 53 queries.
* [`📂 Detection Engineering Module (Sigma Rule)`](./google-cybersecurity/detection-engineering/) — Vendor-Neutral Detection Rules (`sigma_failed_logins.yml`).

### 🌐 3. Web Application & Emerging AI Security
* [`📂 Anti-CSRF Token Middleware`](./google-cybersecurity/web-security/) — Cryptographically secure token generation and validation middleware in Python/Flask.
* [`📂 Adversarial AI Threat Model`](./cloud-security/ai-security/) — Mathematical evasion model (FGSM) detailing gradient manipulation attacks and adversarial training defenses.

### ☁️ 4. Cloud Architecture & Infrastructure as Code (IaC)
* [`📂 Enterprise IAM Policy Library`](./cloud-security/iam-security/) — Multi-cloud JSON policies enforcing IP CIDR locks and mandatory MFA conditions.
* [`📂 Enforce In-Transit Encryption`](./cloud-security/iam-security/enforce_tls_policy.json) — Zero-trust S3 guardrail policy denying any cleartext HTTP transport requests.
* [`📂 Secure Terraform VPC Baseline`](./cloud-security/secure-infrastructure/) — IaC module spinning up private network tiers and stateful HTTPS perimeter firewalls.
* [`📂 Cloud Threat Deception Honeytoken`](./cloud-security/threat-deception/) — Terraform S3 Canary trap paired with EventBridge real-time access alert triggers.

### ⚙️ 5. DevSecOps & Continuous Integration
* [`📂 CI/CD Security Pipeline`](./.github/workflows/security_scan.yml) — GitHub Actions pipeline automatically scanning commits with Bandit and Checkov.

---

## 🚀 DevSecOps Pipeline Status
This repository utilizes automated Static Application Security Testing (SAST). Every code commit triggers an automated pipeline that validates Terraform configurations against CIS benchmarks and parses Python code for security flaws.

---
*Maintained by **[Mikael/Mikarl]** — Connect with me on [LinkedIn](https://www.linkedin.com/in/mikael-beck-b60999203) or explore my technical write-ups above.*