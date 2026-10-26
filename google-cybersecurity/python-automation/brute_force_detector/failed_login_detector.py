"""Detect per-source failed-login bursts in timestamped authentication logs."""

import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"Failed login attempt from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b"
)


def detect_brute_force(log_file, threshold=5, window_seconds=300):
    """Return IPs whose failed-login count reaches threshold within the time window."""
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")

    timestamps_by_ip = defaultdict(list)
    with open(log_file, "r", encoding="utf-8") as source:
        for line in source:
            match = LOG_PATTERN.search(line)
            if not match:
                continue
            try:
                address = str(ipaddress.ip_address(match.group("ip")))
                timestamp = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            timestamps_by_ip[address].append(timestamp)

    alerts = {}
    window = timedelta(seconds=window_seconds)
    for address, timestamps in timestamps_by_ip.items():
        timestamps.sort()
        left = 0
        max_count = 0
        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window:
                left += 1
            max_count = max(max_count, right - left + 1)
        if max_count >= threshold:
            alerts[address] = max_count
    return alerts


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_file", nargs="?", default="server_auth.log")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    alerts = detect_brute_force(args.log_file, args.threshold, args.window_seconds)
    if not alerts:
        print("No failed-login burst exceeded the configured threshold.")
        return
    for address, count in sorted(alerts.items()):
        print(f"ALERT: {address} had {count} failures within {args.window_seconds} seconds")


if __name__ == "__main__":
    main()
