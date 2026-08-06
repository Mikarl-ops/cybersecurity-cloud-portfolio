"""
Filename: cloudtrail_evasion_detector.py
Description: Parses raw AWS CloudTrail JSON log streams to flag critical defense 
             evasion events, such as unauthorized log disabling or trail deletion.
Focus: Automated detection of adversary persistence and defense evasion tactics, specifically targeting API calls that stop logging (StopLogging) or delete audit trails (DeleteTrail).
"""

import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# MITRE ATT&CK T1562.002: Impair Defenses - Disable Cloud Logs
EVASION_EVENT_NAMES = {
    "StopLogging": "CRITICAL: CloudTrail logging was suspended!",
    "DeleteTrail": "CRITICAL: A CloudTrail audit log stream was deleted!",
    "UpdateTrail": "WARNING: CloudTrail configuration was modified.",
    "PutEventSelectors": "WARNING: Event selectors modified (potential log suppression)."
}

# Function to analyze CloudTrail logs for defense evasion attempts
def analyze_cloudtrail_log(json_filepath):
    logging.info(f"[*] Ingesting CloudTrail event stream from: {json_filepath}...")

    # Parse the JSON log file and check for defense evasion events
    try:
        with open(json_filepath, 'r') as log_file:
            data = json.load(log_file)
            records = data.get("Records", [])
            
            evasion_count = 0
            for record in records:
                event_name = record.get("eventName")
                event_source = record.get("eventSource")
                user_identity = record.get("userIdentity", {}).get("arn", "Unknown-ARN")
                source_ip = record.get("sourceIPAddress", "Unknown-IP")

                # Check for defense evasion events based on MITRE ATT&CK T1562.002
                if event_source == "cloudtrail.amazonaws.com" and event_name in EVASION_EVENT_NAMES:
                    evasion_count += 1
                    alert_msg = EVASION_EVENT_NAMES[event_name]
                    logging.error(f"[DEFENSE EVASION DETECTED] {alert_msg}")
                    logging.error(f" -> User: {user_identity} | IP: {source_ip} | Action: {event_name}")
                    
            if evasion_count == 0:
                logging.info("[+] No defense evasion signatures detected in log batch.")
                
    except FileNotFoundError:
        logging.error(f"[ERROR] Could not locate file: {json_filepath}")
    except json.JSONDecodeError:
        logging.error("[ERROR] Invalid JSON payload format.")

if __name__ == "__main__":
    # Create a simulated CloudTrail log payload containing a defense evasion attack
    sample_log = "cloudtrail_sample.json"
    simulated_payload = {
        "Records": [
            {
                "eventTime": "2026-08-05T12:00:00Z",
                "eventSource": "cloudtrail.amazonaws.com",
                "eventName": "StopLogging",
                "userIdentity": {"arn": "arn:aws:iam::123456789012:user/attacker_compromised"},
                "sourceIPAddress": "198.51.100.45"
            }
        ]
    }
    
    with open(sample_log, "w") as f:
        json.dump(simulated_payload, f)
        
    analyze_cloudtrail_log(sample_log)