# Validated firewall rule generator

This demo reads one IPv4 or IPv6 address per line, validates the complete feed, removes duplicate addresses, and writes a shell script with idempotent iptables or ip6tables rules. It never executes the generated script. Invalid input stops generation before the output file is changed.

Run from the repository root with Python:

    python google-cybersecurity/python-automation/active_threat_mitigation/firewall_rule_generator.py google-cybersecurity/python-automation/active_threat_mitigation/threat_feed.sample.txt generated-block-rules.sh

The sample feed uses documentation-only IP ranges. Review generated commands and adapt them to the host firewall before use.
