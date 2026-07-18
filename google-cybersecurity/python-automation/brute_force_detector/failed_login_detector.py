"""
Filename: failed_login_detector.py
Description: Parses server authentication logs using Regular Expressions (regex)
             to identify potential brute-force attacks by flagging IP addresses 
             with excessive failed login attempts.
"""

import re

def detect_brute_force(log_file, threshold=5):
    # Dictionary to keep track of { "IP_Address": failed_count }
    failed_attempts = {}
    
    # Regex pattern to match standard IPv4 addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    
    print(f"[*] Analyzing {log_file} for indicators of compromise (IoCs)...")
    
    with open(log_file, "r") as file:
        for line in file:
            # Check if the log line contains a failed login indicator
            if "Failed login attempt" in line:
                # Find the IP address in that specific line using regex
                match = re.search(ip_pattern, line)
                if match:
                    ip = match.group()
                    # Increment the counter for this specific IP address
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # Evaluate the results and trigger alerts for IPs crossing our threshold
    alerts_triggered = 0
    print("\n--- [SECURITY ALERTS] ---")
    for ip, count in failed_attempts.items():
        if count >= threshold:
            print(f"[ALERT] Potential Brute-Force Attack Detected!")
            print(f"        Source IP: {ip}")
            print(f"        Total Failed Attempts: {count}\n")
            alerts_triggered += 1
            
    if alerts_triggered == 0:
        print("[INFO] Security sweep complete. No brute-force signatures detected.")

if __name__ == "__main__":
    # Target our log file and set a threshold of 5 failed attempts
    target_log = "server_auth.log"
    detect_brute_force(target_log, threshold=5)