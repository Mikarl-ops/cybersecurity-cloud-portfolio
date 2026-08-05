"""
Filename: auto_remediate_compromise.py
Description: Automated Incident Response script that simulates revoking IAM user 
             sessions and attaching an isolation Security Group to an EC2 instance 
             upon receiving a high-severity GuardDuty alert.
"""

import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# Simulated remediation functions
def isolate_compromised_instance(instance_id, isolation_sg_id):
    """
    Simulates attaching a zero-ingress isolation Security Group to a target instance.
    """
    logging.warning(f"[ACTION] Isolating EC2 Instance: {instance_id}")
    logging.info(f" -> Removing existing Security Groups from {instance_id}...")
    logging.info(f" -> Attaching Isolation Security Group ({isolation_sg_id}) denying all traffic.")
    return True

# Simulated remediation function for IAM user
def revoke_iam_user_sessions(username):
    """
    Simulates attaching an inline policy denying all API calls for a compromised identity.
    """
    logging.warning(f"[ACTION] Revoking active sessions for IAM User: {username}")
    deny_all_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    }
    logging.info(f" -> Applying inline DenyAll policy to user: {username}")
    return True

# Main processing function
def process_guardduty_finding(event_payload):
    """
    Parses incoming GuardDuty threat findings and triggers appropriate remediation.
    """
    finding_type = event_payload.get("detail", {}).get("type", "Unknown")
    severity = event_payload.get("detail", {}).get("severity", 0)
    resource = event_payload.get("detail", {}).get("resource", {})

    logging.info(f"[*] Processing GuardDuty Finding: '{finding_type}' (Severity: {severity})")
    
    # High Severity threshold (Severity >= 7.0)
    if severity >= 7.0:
        if "EC2" in finding_type:
            instance_id = resource.get("instanceDetails", {}).get("instanceId", "i-unknown")
            isolate_compromised_instance(instance_id, isolation_sg_id="sg-isolation-quarantine-001")
            
        elif "IAMUser" in finding_type:
            username = resource.get("accessKeyDetails", {}).get("userName", "unknown-user")
            revoke_iam_user_sessions(username)
    else:
        logging.info("[*] Finding severity below critical threshold. Alerting SOC channel only.")

# Entry point for testing the script
if __name__ == "__main__":
    # Simulated high-severity GuardDuty payload (UnauthorizedAccess:EC2/TorRelay)
    sample_guardduty_alert = {
        "detail": {
            "severity": 8.5,
            "type": "UnauthorizedAccess:EC2/TorIPCaller",
            "resource": {
                "instanceDetails": {
                    "instanceId": "i-0a1b2c3d4e5f67890"
                }
            }
        }
    }
    
    print("--- SIMULATING AUTOMATED SOAR REMEDIATION PIPELINE ---")
    process_guardduty_finding(sample_guardduty_alert)