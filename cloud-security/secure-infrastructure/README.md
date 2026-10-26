# AWS network baseline example

This Terraform project declares an AWS VPC, a subnet with no internet-gateway route, and a security group that allows HTTPS from a configurable CIDR. The security group is not attached to a workload, and no workload is created, so the rules are a reusable starting point rather than an enforced boundary on a running service.

The default CIDR is a documentation-only placeholder. Configure an authorized range before deployment. Review the Terraform plan and potential cloud charges, then remove lab resources after use. CI checks formatting and Terraform syntax; it does not deploy the configuration.

Possible next increments are an explicit route table, flow-log delivery, a sample workload with a teardown path, and a deployment test in an isolated account.
