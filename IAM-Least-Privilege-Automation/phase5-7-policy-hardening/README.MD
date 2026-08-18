# Project Aegis: Policy Hardening & CI/CD Enforcement

Project Aegis is a Rego-based security guardrail for Terraform infrastructure plans. The policy is designed to prevent insecure AWS Security Group configurations from reaching deployment.

The project evolved through several rounds of testing and review, with each phase addressing a specific security or implementation gap.

---

## What the policy enforces

Aegis currently evaluates:

- Public IPv4 CIDRs
- Public IPv6 CIDRs
- RFC1918 private IPv4 networks
- Restricted ports
- Restricted ports hidden inside wider port ranges
- Wildcard protocol `-1`
- Inline `aws_security_group` ingress rules
- Standalone `aws_security_group_rule` ingress resources
- Terraform plans generated from actual Terraform configuration

Restricted ports currently include:

```rego
restricted_ports := {22, 3306, 3389, 5432}
