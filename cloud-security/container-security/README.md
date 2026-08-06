# Project: Kubernetes Microservice Zero-Trust Segmentation

## 📋 Project Overview
This project defines declarative Kubernetes `NetworkPolicy` manifests to enforce microsegmentation within containerized environments, preventing unauthorized lateral movement across cluster namespaces.

## 🛠️ STAR Analysis
* **Situation:** Default Kubernetes configurations allow unconstrained flat networking, meaning any compromised pod can freely scan and access adjacent microservices or database pods.
* **Task:** Implement an ingress/egress filter model restricting database tier access exclusively to designated payment processing APIs over authorized ports.
* **Action:** Authored a dual-policy YAML structure: a universal `default-deny-all` isolation baseline paired with explicit label-matched rules targeting `app: payment-service` over TCP port 5432.
* **Result:** Replaced flat container connectivity with zero-trust network boundaries, containing pod breaches to their immediate workload scope.