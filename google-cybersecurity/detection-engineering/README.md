# Linux SSH failed-login Sigma example

The rule targets Linux SSH authentication messages and counts matching failures per source in a five-minute window. It does not use Windows Event ID 4625.

The rule expects the backend to map raw SSH messages to message and source-IP fields. Confirm that mapping for the selected log source and Sigma backend before using the rule. The rule is marked experimental and has not been exercised against a production SIEM in this repository.

The standalone detection-engineering lab repo adds synthetic events and unit tests for the matching threshold.
