# Project Variation: Automated Firewall Rule Generator

## 📋 Project Overview
This project expands on log monitoring by building an automated remediation tool. The Python script ingests a threat feed of malicious IP addresses and automatically constructs an executable Linux bash script containing `iptables` rules to immediately block inbound traffic from those vectors.

## 🛠️ STAR Analysis
* **Situation:** During an active distributed denial-of-service (DDoS) or brute-force campaign, manually typing firewall rules into the command line to block hundreds of IP addresses is too slow to prevent system degradation.
* **Task:** Build an automated ingestion script that translates plain-text lists of attacker IP addresses into standardized Linux kernel firewall commands.
* **Action:** Utilized Python file I/O operations and string formatting to dynamically wrap isolated IP strings into executable syntax (`iptables -A INPUT -s <IP> -j DROP`), outputting a ready-to-run `.sh` remediation script.
* **Result:** Reduced the mean time to remediate (MTTR) active perimeter threats from hours of manual entry to seconds of automated rule execution.