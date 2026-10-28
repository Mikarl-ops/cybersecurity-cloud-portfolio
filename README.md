# Cybersecurity & Cloud Security Portfolio

Security automation, cloud detection, detection engineering, and evidence-led incident response projects. This portfolio brings together runnable local tools, detection rules, configuration examples, and investigation write-ups.

Featured work is labeled by its evidence and deployment scope so readers can distinguish synthetic exercises and local validation from live services.

**Navigate:** [Featured labs](#featured-labs) · [Additional projects](#additional-projects-in-this-repository) · [Run the Python demos](#run-the-python-demos) · [Scope and data handling](#scope-and-data-handling) · [CI](#ci)

## Featured labs

### [CloudTrail Response Lab](https://github.com/Mikarl-ops/aws-cloudtrail-response-lab)

Parses failed AWS console sign-in events into structured, analyst-guided triage alerts.

- **Demonstrates:** CloudTrail event filtering and parsing, Python tests for malformed and non-matching events, structured alert design, and an event-driven AWS architecture with scoped permissions.
- **Scope:** Uses synthetic events. Dry-run is the default; tests exercise notification behavior with a mocked SNS client. Terraform describes optional AWS resources but has not been deployed here. The function does not perform automatic containment.
- **Explore:** [README and architecture](https://github.com/Mikarl-ops/aws-cloudtrail-response-lab#readme) · [Lambda handler](https://github.com/Mikarl-ops/aws-cloudtrail-response-lab/blob/main/lambda/handler.py) · [Tests](https://github.com/Mikarl-ops/aws-cloudtrail-response-lab/tree/main/tests) · [Terraform](https://github.com/Mikarl-ops/aws-cloudtrail-response-lab/tree/main/terraform)

### [Security Detection Engineering Lab](https://github.com/Mikarl-ops/security-detection-engineering-lab)

A Sigma rule and local Python evaluator detect at least five failed SSH authentications from one source IP within a rolling 300-second window.

- **Demonstrates:** Detection-as-code, threshold and time-boundary testing, input validation, and false-positive analysis with analyst triage guidance.
- **Scope:** The supplied authentication events are synthetic. The evaluator is a local reference implementation; the Sigma rule needs field mapping and validation in the target SIEM before operational use.
- **Explore:** [README and test coverage](https://github.com/Mikarl-ops/security-detection-engineering-lab#readme) · [Sigma rule](https://github.com/Mikarl-ops/security-detection-engineering-lab/blob/main/detections/linux_ssh_bruteforce.yml) · [Python evaluator](https://github.com/Mikarl-ops/security-detection-engineering-lab/blob/main/src/ssh_bruteforce.py) · [Tests](https://github.com/Mikarl-ops/security-detection-engineering-lab/tree/main/tests)

### [DFIR Case Files](https://github.com/Mikarl-ops/dfir-case-files)

A reproducible analyzer and investigation report built around synthetic authentication, DNS, and CloudTrail records.

- **Demonstrates:** UTC timeline normalization, event-level evidence traceability, confidence assessments, alternative explanations, evidence gaps, and evidence-led follow-up recommendations.
- **Scope:** Case 001 is a synthetic triage exercise, not a real incident. It includes no real user data or packet capture, and its heuristics do not establish compromise, DNS exfiltration, or a connection between the SSH and CloudTrail events.
- **Explore:** [Project README](https://github.com/Mikarl-ops/dfir-case-files#readme) · [Case 001 incident report](https://github.com/Mikarl-ops/dfir-case-files/blob/main/cases/001-suspicious-auth-and-dns/incident-report.md) · [Analyzer](https://github.com/Mikarl-ops/dfir-case-files/blob/main/src/analyze_case.py) · [Tests](https://github.com/Mikarl-ops/dfir-case-files/tree/main/tests)

## Additional projects in this repository

| Area | Project | Status and scope |
| --- | --- | --- |
| Python automation | [Allow list updater](./google-cybersecurity/python-automation/Automated%20Log%20File%20Access/) | Runnable local file-processing demo |
| Python automation | [Brute-force detector](./google-cybersecurity/python-automation/brute_force_detector/) | Runnable log analysis demo with a five-minute threshold |
| Python automation | [Firewall rule generator](./google-cybersecurity/python-automation/active_threat_mitigation/) | Validates IP input and writes a reviewable shell script; it never applies rules |
| Threat intelligence | [NVD CVE lookup](./google-cybersecurity/python-automation/Threat_intelligence_API_automation/) | Calls the public NVD API; requires network access |
| Cloud detection | [CloudTrail evasion detector](./google-cybersecurity/python-automation/evasion-detector/) | Parses CloudTrail JSON and returns matching findings |
| Incident response | [GuardDuty response simulation](./cloud-security/automated-response/) | Simulates response planning; makes no AWS API calls |
| Linux security | [Linux hardening audit](./google-cybersecurity/system-security/) | Read-only checks for selected SSH settings, listening ports, and temporary files |
| SQL investigation | [Login and privilege audit queries](./google-cybersecurity/linux-sql/) | Query examples; adapt table and field names to your dataset |
| Network forensics | [Wireshark investigation walkthrough](./google-cybersecurity/network-security/) | Written example only; the repository does not include a packet capture |
| Detection engineering | [Linux SSH failed-login Sigma rule](./google-cybersecurity/detection-engineering/) | Rule example; field mapping depends on the log source |
| Web security | [CSRF protection demo](./google-cybersecurity/web-security/) | Small Flask example with a token endpoint and tests |
| Cloud IAM | [AWS and GCP policy examples](./cloud-security/iam-security/) | Illustrative policies using placeholder identities and resources |
| Infrastructure as code | [AWS network baseline](./cloud-security/secure-infrastructure/) | Terraform configuration for a VPC, subnet, and security group; no workload is deployed |
| Threat deception | [S3 canary alert example](./cloud-security/threat-deception/) | Terraform example; requires CloudTrail S3 data events for object-access visibility |
| Container security | [Kubernetes network policies](./cloud-security/container-security/) | Example default-deny and database-ingress policies |
| DevSecOps | [GitHub Actions security workflow](./.github/workflows/security_scan.yml) | Runs tests and security/configuration scans |

## Run the Python demos

Use Python 3.11 or newer. Install the demo and development dependencies with **pip install -r requirements-dev.txt**. Run the local test suite from the repository root with **python -m unittest discover -s tests -v**.

The firewall generator takes an IP feed and an output path. It validates the full feed before writing a script. Review generated rules before applying them to any system. The NVD lookup calls an external service; the other included Python examples can be run with local files and sample data.

## Scope and data handling

The featured labs use synthetic event fixtures or configuration-only AWS resources; no live AWS deployment or integration is represented. Examples use documentation-only IP ranges. AWS and GCP policies are templates, not account-specific recommendations. The GuardDuty handler is a simulation, the network forensics project is a walkthrough without a PCAP, and the Terraform projects have not been deployed as production infrastructure. Project write-ups describe intended use and current limitations; performance or security outcomes are not claimed unless backed by measurements in the repository.

## CI

GitHub Actions runs the Python unit tests and Bandit as blocking checks, validates Terraform formatting and syntax, and scans Terraform with Checkov in advisory mode while the baseline is being established. Gitleaks scans repository history for exposed secrets. The workflow grants the repository token read-only access.

---

Maintained by Mikael Beck.
