# IAM Least Privilege Automation

This project is about building guardrails. Not just detecting problems after 
they happen, but thinking like an attacker and closing gaps before they can 
be exploited. It started as a one-time IAM audit and expanded into a 
multi-phase cloud security pipeline covering identity, storage, network, 
and policy enforcement.

Built on AWS, Python, Terraform, and Open Policy Agent across five phases.

---

## Phases

### Phase 1 — Static Least Privilege Analysis
Analyzed 90 days of CloudTrail logs to identify IAM roles carrying permissions 
they had never used. Wrote a custom Python script using boto3 to automate the 
detection, classify roles by risk level, and output a findings report. Applied 
Terraform to replace broad AWS managed policies with narrow, task-specific ones.

Result: 67 permissions reduced to 3. Wildcard permissions eliminated entirely. 
96% reduction. IAM Access Analyzer confirmed zero High or Critical findings.

Tools: Python, boto3, Terraform, AWS CLI, CloudTrail, IAM Access Analyzer

[View files](terraform/) · [Analysis script](analyze_iam.py)

---

### Phase 2 — Continuous Identity Guarding
Converted the one-time script into a scheduled Lambda function that runs 
every 30 days automatically. Added ghost role detection — any role with zero 
activity older than 90 days gets flagged for decommissioning. Results delivered 
by email via SNS after every run. Also documented a Service Control Policy 
to prevent wildcard permissions from being created at the organization level.

Tools: AWS Lambda, EventBridge, SNS, Python, boto3

[View files](continuous-identity-guarding/)

---

### Phase 3 — Project Aegis: CSPM Engine
Expanded from IAM-only scanning into a full Cloud Security Posture Management 
engine covering four domains: IAM privilege analysis, cross-account trust 
relationships, S3 storage exposure, and network ingress controls. All findings 
delivered in a single unified email report after every automated run.

Also built a real-time out-of-band remediation layer — when an insecure 
security group or S3 misconfiguration is detected via CloudTrail and 
EventBridge, the engine automatically rolls it back using cross-account 
STS credentials. Remediation latency: 337ms.

Tools: AWS Lambda, EventBridge, CloudTrail, SNS, boto3, STS

[View CSPM scanner](project-aegis/) · [View remediation engine](aegis-remediation-engine/)

---

### Phase 3.5 — Proactive Inline Policy Enforcement
Shifted from reactive remediation to proactive blocking. Instead of fixing 
misconfigurations after they reach AWS, this phase evaluates Terraform plans 
before deployment using Open Policy Agent and Rego. If a plan defines a 
security group with SSH or RDP open to the internet, the policy returns a 
deny and the pipeline exits with a non-zero status. The resource never gets 
created. Exposure window drops from 337ms to zero.

Also refactored the Lambda function — removed all AWS mutation permissions 
since there is nothing left to remediate, replaced with a lightweight 
telemetry function that logs blocked attempts to SNS.

Tools: OPA, Rego, Terraform, AWS Lambda, SNS, Kali Linux

---

### Phase 4 — Scaled Rego and Policy Unit Testing
Hardened the policy engine for production use. Replaced named index 
iteration with universal quantifiers so every array entry in a Terraform 
plan gets evaluated, not just the first match. Replaced string-based CIDR 
matching with net.cidr_contains — meaning a rule written as 0.0.0.0/1 
gets caught just like 0.0.0.0/0, because it is doing network math instead 
of text comparison. Wrote an automated unit test suite using OPA's native 
testing framework to prove both directions: insecure configs get denied, 
clean configs pass clean.

Tools: OPA, Rego, Kali Linux

[View files](project-aegis-phase4/)

---

## Results

| Metric | Start | End |
|---|---|---|
| IAM permissions on target role | 67 | 3 |
| Wildcard permissions | 8 | 0 |
| Risk classification | CRITICAL | Resolved |
| Remediation latency (reactive) | 30 days | 337ms |
| Exposure window (proactive) | 337ms | 0ms |
| Manual runs required | Every time | 0 |

---

## Stack

AWS IAM Access Analyzer, CloudTrail, EventBridge, Lambda, SNS, STS,
Python 3, boto3, Terraform, Open Policy Agent, Rego, AWS CLI v2,
Kali Linux (aarch64)

---

## References

- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/)
- [NIST SP 800-53 AC-6 Least Privilege](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)

---
