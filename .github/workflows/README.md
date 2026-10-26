# Security workflow

The workflow runs on pushes and pull requests targeting main. Its blocking checks are the Python unit suite, Bandit, Terraform formatting, and Terraform validation. Checkov currently reports Terraform security findings in advisory mode while the examples are being brought to a reviewed baseline. Gitleaks scans repository history. The workflow uses a read-only repository token permission.

The Terraform projects are validated without AWS credentials and are not deployed by CI.
