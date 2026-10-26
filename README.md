# Cybersecurity & Cloud Security Portfolio

A portfolio of security automation, detection, incident response, cloud controls, and infrastructure security examples. Projects are labelled by what currently exists so readers can distinguish runnable demonstrations from written case studies and configuration templates.

## Featured projects

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

## How to read the project claims

Examples use synthetic records and documentation-only IP ranges. AWS and GCP policies are templates, not account-specific recommendations. The GuardDuty handler is a simulation, the network forensics project is a walkthrough without a PCAP, and the Terraform projects have not been deployed as production infrastructure. Project write-ups describe intended use and current limitations; performance or security outcomes are not claimed unless backed by measurements in the repository.

## CI

GitHub Actions runs the Python unit tests and Bandit as blocking checks, validates Terraform formatting and syntax, and scans Terraform with Checkov in advisory mode while the baseline is being established. Gitleaks scans repository history for exposed secrets. The workflow grants the repository token read-only access.

---
Maintained by Mikael Beck.
