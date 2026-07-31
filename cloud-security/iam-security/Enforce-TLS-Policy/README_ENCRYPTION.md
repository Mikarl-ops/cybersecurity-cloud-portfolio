# Project Variation: Enforcing In-Transit Encryption via IAM

## 📋 Project Overview
This project showcases a zero-trust cloud guardrail policy. This JSON configuration strictly denies all API requests made against sensitive object storage assets if the payload is not encrypted in transit using HTTPS/TLS.

## 🛠️ STAR Analysis
* **Situation:** Developers or automated scripts sometimes misconfigure AWS SDKs to use standard HTTP endpoints, exposing sensitive customer payloads to eavesdropping or packet interception across networks.
* **Task:** Implement an immutable cloud policy that forces all client connections to upgrade to encrypted transport protocols, automatically rejecting unencrypted traffic before it reaches the storage tier.
* **Action:** Authored a bucket-level IAM policy utilizing an explicit `Deny` effect paired with a universal `Principal` wildcard (`*`). Applied the condition key `"aws:SecureTransport": "false"` to intercept and drop any requests lacking valid SSL/TLS handshakes.
* **Result:** Completely eliminated cleartext data transmissions to target cloud assets, satisfying strict PCI-DSS and HIPAA data-in-transit compliance requirements.