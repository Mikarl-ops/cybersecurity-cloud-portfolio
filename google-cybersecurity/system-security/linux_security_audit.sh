#!/bin/bash
# ==============================================================================
# File: linux_security_audit.sh
# Description: Performs basic system hardening checks on a Linux host (SSH config,
#              open listening ports, and world-writable files).
# This script is intended for educational purposes and should be run with caution.
# Make sure to review and understand the checks before executing on production systems.
# To make the script executable, run: chmod +x google-cybersecurity/system-security/linux_security_audit.sh
# ==============================================================================

echo "=========================================="
echo "    LINUX SECURITY & HARDENING AUDIT      "
echo "=========================================="

# 1. Check SSH Configuration Settings
echo -e "\n[*] Checking SSH Hardening Configuration..."
SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    # Check Root Login
    if grep -qE "^PermitRootLogin no" "$SSH_CONFIG"; then
        echo "[PASS] Root SSH login is disabled."
    else
        echo "[WARN] Root SSH login may be enabled! Ensure 'PermitRootLogin no' is set."
    fi

    # Check Password Authentication
    if grep -qE "^PasswordAuthentication no" "$SSH_CONFIG"; then
        echo "[PASS] Password authentication is disabled (Key-based auth enforced)."
    else
        echo "[WARN] Password authentication is allowed. Consider enforcing SSH keys."
    fi
else
    echo "[INFO] SSH config file not found at $SSH_CONFIG."
fi

# 2. Check Active Listening Network Ports
echo -e "\n[*] Checking Open Listening Ports..."
netstat -tuln 2>/dev/null || ss -tuln

# 3. Check for World-Writable Directories
echo -e "\n[*] Auditing for World-Writable Files in /tmp..."
find /tmp -maxdepth 2 -perm -0002 -type f 2>/dev/null | head -n 10

echo -e "\n[+] Audit Complete."