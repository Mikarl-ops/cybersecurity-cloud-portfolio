# Project 3: Incident Investigation with SQL

## 📋 Project Overview
This project showcases my ability to utilize Relational Database Management Systems (RDBMS) and SQL syntax to perform forensic log analysis. It outlines the data queries used to isolate compromised accounts and catch suspicious internal network reconnaissance.

## 🛠️ STAR Analysis

* **Situation:** The Security Operations Center (SOC) flagged an alert regarding potential unauthorized file access. The raw event stream was stored in massive relational database tables, requiring precise querying to separate malicious indicators from legitimate corporate employee traffic.
* **Task:** Formulate a series of optimized SQL queries to audit access logs, extract after-hours failed connection anomalies, track specific high-risk user profiles (`jdoe`), and identify geographic/network distribution spikes.
* **Action:** 
  * Developed conditional logic strings using `WHERE`, `AND`, and time-casting operators (`TIME(login_time)`) to filter out thousands of benign daylight operations.
  * Deployed wildcard syntax structures (`LIKE '%financial%'`) to catch unauthorized internal system mapping and data snooping signatures.
  * Constructed relational aggregation mechanisms using `GROUP BY` paired with `HAVING` filters to highlight accounts violating standard corporate device access limits.
* **Result:** Successfully isolated an insider threat signature pattern and narrowed down a list of rogue external IPs hitting the corporate environment after hours, allowing the firewall team to promptly update active blocking rules.