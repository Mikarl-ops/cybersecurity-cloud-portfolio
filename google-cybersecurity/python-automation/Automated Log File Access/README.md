# Project 1: Automated Access Control File Updater

## 📋 Project Overview
This project demonstrates an automated solution for managing network perimeter security. It features a Python script designed to parse, analyze, and remediate unauthorized access permissions within a corporate 'allow list' text file.

## 🛠️ STAR Analysis

* **Situation:** Security operations frequently identify compromised or revoked external IP addresses that must be immediately barred from accessing corporate resources. Manually modifying access control lists is prone to human error and creates critical response latency.
* **Task:** Develop a reliable Python script to open a master access file, parse its contents, evaluate it against a checklist of banned IP addresses, strip out unauthorized entries, and safely save the updated configurations.
* **Action:** 
  * Implemented a robust context manager (`with open()`) to handle file I/O operations safely.
  * Utilized `.read()` and `.split()` methods to ingest text blocks and translate raw strings into structured data arrays.
  * Created iterative conditional logic (`for` loops and `if` checkpoints) to accurately identify and isolate targeted strings without altering adjacent data.
  * Combined data structures using `.join()` to reconstruct compliant configuration outputs.
* **Result:** Replaced slow, manual administrative workflows with an automated, scriptable function capable of instantly revoking access parameters, reducing security posture exposure times to near-zero.