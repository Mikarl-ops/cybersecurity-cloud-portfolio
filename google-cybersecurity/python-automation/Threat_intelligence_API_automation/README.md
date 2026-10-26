# NVD CVE lookup

This command-line example queries the NVD CVE API by keyword and returns records with a configurable minimum CVSS severity. It URL-encodes the query, applies a request timeout, and reports API failures as errors.

Run it with Python and network access:

    python cve_threat_intel.py terraform --min-severity HIGH --max-results 20

NVD results depend on the query and source metadata. The output is a triage aid, not a patch-priority decision; assess affected versions, exploitability, and asset exposure separately. Tests use a mocked API response and do not contact NVD.
