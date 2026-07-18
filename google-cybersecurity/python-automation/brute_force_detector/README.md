# Project 2: Automated Brute-Force Attack Detector

## 📋 Project Overview
This project contains an automated security log analysis engine written in Python. It parses production-style server authentication logs using Regular Expressions (`re`) to pinpoint malicious external scanning and credential stuffing activities.

## 🛠️ STAR Analysis

* **Situation:** Security teams monitor high volumes of connection logs daily. Attackers utilize automated tools to rapidly guess credentials (brute-forcing), masking their footprint amidst thousands of legitimate logs. Catching them requires programmatic vigilance.
* **Task:** Develop an automation script that can ingest an unstructured auth log file, parse line items for failure parameters, isolate the attacker's IP string via regular expressions, and alert the SOC if an entity crosses a critical threat threshold.
* **Action:** 
  * Leveraged Python's built-in `re` module with an optimized boundary pattern (`\b(?:\d{1,3}\.){3}\d{1,3}\b`) to accurately extract IPv4 addresses.
  * Designed an iterative line-by-line file reader to minimize memory allocation overhead when processing massive log structures.
  * Implemented a data-hash mapping mechanism (Python `dict`) to maintain structural tracking of anomalous events per specific attacker signature.
* **Result:** Successfully flagged `203.0.113.5` as a malicious vector after detecting 5 rapid failed login signatures, allowing automated alerting engines to pass the threat up the security stack for immediate perimeter blocking.