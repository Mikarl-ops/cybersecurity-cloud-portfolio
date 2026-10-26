"""Find CloudTrail events that may indicate an attempt to impair logging."""

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

EVASION_EVENT_NAMES = {
    "StopLogging": "CloudTrail logging was suspended",
    "DeleteTrail": "A CloudTrail trail was deleted",
    "UpdateTrail": "CloudTrail configuration was modified",
    "PutEventSelectors": "CloudTrail event selectors were modified",
}


def analyze_cloudtrail_log(json_filepath):
    """Return normalized findings from a CloudTrail JSON file."""
    try:
        data = json.loads(Path(json_filepath).read_text(encoding="utf-8"))
    except FileNotFoundError:
        logging.error("Could not locate file: %s", json_filepath)
        return []
    except json.JSONDecodeError:
        logging.error("Invalid JSON payload format in %s", json_filepath)
        return []

    records = data.get("Records", []) if isinstance(data, dict) else []
    if not isinstance(records, list):
        logging.error("CloudTrail Records must be a list")
        return []

    findings = []
    for record in records:
        if not isinstance(record, dict):
            continue
        event_name = record.get("eventName")
        if record.get("eventSource") != "cloudtrail.amazonaws.com" or event_name not in EVASION_EVENT_NAMES:
            continue
        identity = record.get("userIdentity")
        identity = identity if isinstance(identity, dict) else {}
        findings.append({
            "event_time": record.get("eventTime"),
            "event_name": event_name,
            "description": EVASION_EVENT_NAMES[event_name],
            "user_arn": identity.get("arn", "Unknown-ARN"),
            "source_ip": record.get("sourceIPAddress", "Unknown-IP"),
        })
    return findings


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cloudtrail_json", help="Path to a CloudTrail JSON event file")
    args = parser.parse_args()
    findings = analyze_cloudtrail_log(args.cloudtrail_json)
    for finding in findings:
        logging.warning(
            "%s: %s user=%s source_ip=%s",
            finding["event_name"], finding["description"],
            finding["user_arn"], finding["source_ip"],
        )
    logging.info("Analysis complete: %s finding(s)", len(findings))


if __name__ == "__main__":
    main()
