# Project 6: Infrastructure-as-Code (IaC) Secure Perimeter

## 📋 Project Overview
This project contains declarative Terraform configurations engineered to provision a securely architected network baseline on cloud infrastructure. It demonstrates automated segregation of workloads and strict stateful packet filtering.

## 🛠️ STAR Analysis

* **Situation:** Configuring cloud networks manually via the graphical console introduces significant drifting variance and human oversight risks. Misconfigured security groups or accidental exposure of subnet tiers directly to the public internet can lead to rapid compromise.
* **Task:** Code a reusable, modular Terraform blueprint that establishes an isolated, private network boundary and embeds stateful firewall rules restricting perimeter traversal.
* **Action:** 
  * Wrote a custom Virtual Private Cloud (VPC) blueprint with DNS support and logging integrations specified natively.
  * Architected strict subnet isolation, deploying internal resources inside a non-routable private CIDR tier lacking an internet gateway mapping.
  * Formulated stateful security group rules using explicit ingress limits that discard all public scans, restricting entry exclusively to an enterprise trusted netblock (`192.0.2.0/24`) over port 443.
* **Result:** Replaced error-prone provisioning templates with a deterministic infrastructure deployment module, baking zero-trust networking parameters straight into the initial pipeline layout.