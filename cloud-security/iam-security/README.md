# Project 5: Enterprise Least-Privilege IAM Policy Library

## 📋 Project Overview
This project establishes a hardened multi-cloud Identity and Access Management (IAM) framework. It features production-grade JSON policy configurations designed to enforce the Principle of Least Privilege (PoLP) and prevent unauthorized modifications to sensitive data and logging structures.

## 🛠️ STAR Analysis

* **Situation:** Over-privileged access identities represent one of the single greatest vectors for cloud breaches. Relying on default broad admin policies allows compromised employee credentials or misconfigured services to lead to widespread data exfiltration or log tampering.
* **Task:** Engineer highly restricted, declarative security policies in JSON that isolate object storage assets and protect logging sinks, introducing contextual conditional access baselines.
* **Action:** 
  * Authored fine-grained resource arrays targetting only specific corporate buckets rather than using global wildcards (`*`).
  * Implemented strict logical primitives (`IpAddress`, `Bool`) requiring Multi-Factor Authentication (MFA) enforcement and trusted CIDR network blocks (`192.0.2.0/24`).
  * Structured explicit policy guardrails using conditional expressions to strip operational resource modification rights away from standard compute engineer roles.
* **Result:** Eliminated horizontal moving privileges for compromised identities, ensuring critical log pipelines cannot be blinded by threat actors and sensitive data can only be viewed through validated corporate access channels.