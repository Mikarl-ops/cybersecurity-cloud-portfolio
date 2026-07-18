# Project 4: Wireshark Packet Analysis & Anomaly Detection

## Project Overview
This project demonstrates packet-level network forensic analysis using Wireshark. It outlines the tactical steps taken to isolate, analyze, and remediate a suspected network anomaly within a corporate subnet.

## STAR Analysis

* **Situation:** The intrusion detection system (IDS) triggered an alert indicating a sudden, massive spike in inbound TCP traffic targeting a critical internal web server, threatening a denial-of-service (DoS) condition.
* **Task:** Ingest and analyze a raw packet capture (`.pcap`) file to determine the root cause of the traffic spike, isolate the offending external IP addresses, verify if any data or credentials were compromised, and recommend mitigation steps.
* **Action:** 
  * Applied Wireshark display filters (`tcp.flags.syn == 1 && tcp.flags.ack == 0`) to evaluate the ratio of incomplete connections and confirm a **TCP SYN Flood Attack**.
  * Isolated the primary threat vector to rogue external IP address `198.51.100.42` sending over 15,000 requests per minute.
  * Inspected protocol hierarchies and applied the filter `http.request.method == "POST"` to audit active web server interactions. Discovered unencrypted HTTP basic authentication attempts being transmitted in cleartext.
* **Result:** Identified the attack fingerprint as a distributed SYN Flood combined with a brute-force web login attempt. Recommended immediate boundary firewall drop rules for the malicious subnet and initiated a change order to enforce TLS encryption on all internal web portals.

---

## Step-by-Step Forensic Walkthrough

```text
[PHASE 1: IDENTIFYING THE ATTACK SIGNATURE]
Upon opening the network capture file, the protocol hierarchy overview showed an 
overwhelming volume of TCP traffic compared to baseline metrics. 

To determine if this was a coordinated SYN Flood, I utilized the following display 
filter to isolate TCP synchronization requests missing an acknowledgment flag:

Filter: tcp.flags.syn == 1 && tcp.flags.ack == 0

Analysis: The results revealed a massive sequence of packets sent to port 80 with 
sequential source ports, verifying a classic resource-exhaustion attack pattern.


[PHASE 2: ISOLATING THE ATTACKER]
By analyzing the conversations panel (Statistics > Conversations > TCP), I mapped 
out the highest-volume talkers on the wire. A single external host was responsible 
for over 85% of the anomalous traffic:

* Attacker IP: 198.51.100.42
* Target Server IP: 10.0.0.5

Using this IP, I filtered the packet stream explicitly to inspect all payloads 
originating from this host:

Filter: ip.src == 198.51.100.42


[PHASE 3: PROTOCOL INSPECTION & VULNERABILITY DISCOVERY]
While filtering for HTTP payloads to see if the attacker was interacting with 
the web application layer, I used the filter:

Filter: http.request.method == "POST" || http.authbasic

Finding: The packet payload inspection showed that the web form was transmitting 
user credentials across standard HTTP instead of HTTPS. The authentication headers 
revealed cleartext strings, posing an immediate credential theft risk to any users 
attempting to authenticate during the attack window.

Remediation & Defenses Recommended
Perimeter Hardening: Implement an automated firewall rate-limiting rule (or deploy a SYN Proxy) to drop traffic from hosts exceeding 100 connections per second.

Cryptographic Enforcement: Deprecate port 80 (HTTP) on the target asset and migrate to port 443 (HTTPS) utilizing TLS 1.3 to ensure all session traffic and credentials are securely encrypted in transit.

---