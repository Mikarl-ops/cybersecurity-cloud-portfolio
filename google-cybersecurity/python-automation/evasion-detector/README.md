# CloudTrail defense-evasion event parser

This parser reads a CloudTrail JSON file and returns normalized findings for StopLogging, DeleteTrail, UpdateTrail, and PutEventSelectors events. It does not connect to AWS or evaluate whether an event was authorized.

Run from the repository root with Python:

    python google-cybersecurity/python-automation/evasion-detector/cloudtrail_evasion_detector.py google-cybersecurity/python-automation/evasion-detector/cloudtrail_sample.json

The sample event is synthetic. Production use needs account context, allowlists, severity rules, and an alert destination.
