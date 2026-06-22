# IAM Least Privilege Automation

Automated detection and remediation of over-privileged IAM roles and real-time infrastructure drift using CloudTrail log analysis, serverless event-driven architectures, and Terraform infrastructure-as-code.

---

## Overview

This project implements a multi-phase security automation pipeline for AWS environments.

* **Phase 1 (Static Analysis):** Analyzes 90 days of CloudTrail activity to isolate unexercised permissions granted to IAM roles, classifies roles by risk level, and applies Terraform-based remediation to replace broad policies with narrow, task-specific variants.
* **Phase 2 (Continuous Remediation):** Deploys a live, out-of-band Cloud Security Posture Management (CSPM) engine to intercept infrastructure mutations instantly, execute cross-account rollbacks via short-lived tokens, and stream telemetry data.

**Success metrics:**

* Reduce High and Critical IAM Access Analyzer findings by 80% without breaking application functionality. **Achieved: 96% reduction.**
* Drop the enterprise threat exploitation window from a 30-day scheduled audit timeline down to a sub-second frame. **Achieved: 337.38ms average auto-remediation response.**

---

## Modules

* [Phase 1: Static Least Privilege Analysis](terraform/) — Analysis script and baseline IAM policy remediation resources.
* [Phase 2: Continuous Identity Guarding](continuous-identity-guarding/) — Real-time Lambda automation, dynamic Boto3 data serialization, multi-account STS handshakes, and Amazon SNS alerting hub.

---

## Stack

* AWS IAM Access Analyzer (Principal Analysis — Unused Access)
* AWS CloudTrail & Amazon EventBridge
* Python 3 + Boto3 (AWS Lambda execution runtime)
* Terraform v1.x
* AWS STS (Cross-Account Security Brokerage)
* Amazon SNS (Central Telemetry Hub)
* AWS CLI v2
* Kali Linux (aarch64)

---

## How It Works

### Phase 1: Batch Remediation Workflow

```text
CloudTrail Logs (90 days)
↓
analyze_iam.py
→ Enumerate all IAM roles
→ Retrieve granted permissions per role
→ Query CloudTrail for used permissions
→ Compute unused = granted - used
→ Classify risk (Critical / High / Medium / Low)
→ Output JSON report
↓
Terraform
→ Create narrow least-privilege policy
→ Attach to role
→ Remove broad managed policies
↓
IAM Access Analyzer
→ Validate 0 High/Critical findings

```

### Phase 2: Live Self-Healing Event Loop

```text
Infrastructure Drift Mutation (e.g., Public Port 22 Ingress Opened)
↓
AWS CloudTrail Event Capture
↓
Amazon EventBridge Pattern Filter (event-pattern.json match)
↓
AWS Lambda Ingestion Engine (lambda_function.py)
→ Verify Zero-Trust boundary compliance
→ Trigger cross-account aws_sts:AssumeRole handshake
→ Invoke data serialization utility (camelCase to PascalCase payload alignment)
→ Fire out-of-band mitigation (revoke_security_group_ingress)
↓
Amazon SNS Alert Channel (Dispatches real-time JSON metrics to SecOps team)

```

---

## Results

| Metric | Before | After | Reduction / Performance |
| --- | --- | --- | --- |
| Permissions granted | 67 | 3 | 96% reduction |
| Wildcard permissions | 8 | 0 | 100% reduction |
| Risk level | CRITICAL | HIGH | Successfully reduced |
| Analyzer findings (High/Critical) | — | 0 | Target met |
| **Remediation processing latency** | **30 days (Scheduled)** | **337.38 ms** | **99.99% reduction** |
| **Local credential dependency** | **Static profiles** | **Dynamic STS** | **Zero-Trust verified** |

---

## Project Structure

```text
iam-analyzer/
├── analyze_iam.py                 # CloudTrail analysis script
├── terraform/
│   ├── provider.tf                # AWS provider configuration
│   ├── main.tf                    # IAM policy remediation resources
│   └── .gitignore                 # Excludes tfstate from version control
└── continuous-identity-guarding/  # Phase 2: Real-time event-driven CSPM engine
    ├── lambda_function.py         # Remediation engine & Boto3 data parser
    ├── iam_policies.tf            # Cross-account & engine execution boundaries
    ├── eventbridge_rule.tf        # CloudTrail filter and target trigger routing
    └── README.md                  # Real-time engine deployment documentation

```

---

## Usage

### Phase 1: Static Asset Remediation

#### 1. Install dependencies

```bash
pip3 install boto3 --break-system-packages

```

#### 2. Configure AWS CLI

```bash
aws configure
aws sts get-caller-identity

```

#### 3. Run analysis

```bash
python3 analyze_iam.py

```

#### 4. Detach existing broad policies

```bash
aws iam detach-role-policy --role-name [role-name] --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam detach-role-policy --role-name [role-name] --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam detach-role-policy --role-name [role-name] --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess

```

#### 5. Apply Terraform remediation

```bash
cd terraform/
terraform init
terraform plan
terraform apply

```

---

### Phase 2: Live Ingestion Engine Deployment

#### 1. Provision Event-Driven Infrastructure

```bash
cd continuous-identity-guarding/
terraform init
terraform apply -auto-approve

```

#### 2. Inject Compliance Drift Test Payload

```bash
aws lambda invoke \
  --function-name Aegis-CSPM-Core-Engine \
  --region us-east-1 \
  --payload file://mock_sg_drift.json \
  output.json

```

#### 3. Validate Live Telemetry Stream

Review local terminal or Amazon CloudWatch log stream to confirm automated mitigation execution metrics match standard runtime patterns:

```text
START RequestId: 166ac039-c316-42fc-86e8-7b631179487c Version: $LATEST
[INFO] Event received: {"source": "aws.ec2", "detail-type": "AWS API Call via CloudTrail"...}
[WARN] Compliance violation: 0.0.0.0/0 ingress opened on sg-0a123b45678cd90ef in account 222222222222!
[INFO] Successfully revoked non-compliant permissions from sg-0a123b45678cd90ef
END RequestId: 166ac039-c316-42fc-86e8-7b631179487c
REPORT RequestId: 166ac039-c316-42fc-86e8-7b631179487c  Duration: 337.38 ms  Billed Duration: 338 ms  Memory Used: 103 MB

```

---

## Key Notes

* **Data Normalization Necessary:** CloudTrail output payloads track object variables via camelCase keys, while Boto3 request stubs demand strict PascalCase styling. The Phase 2 engine abstracts a translation layer (`normalize_ip_permissions`) internally to handle dictionary schema differences out-of-band and protect against `ParamValidation` runtime crashes.
* **Zero-Trust Profile Design:** Local operator configurations (`kepler@kali`) are denied permission to touch cross-account backend systems manually. System handshakes are managed natively on the AWS core event backbone via transient STS access tokens, preventing local desktop credential leaks from compromising account security boundaries.
* **Audit Baseline Requisite:** Requires CloudTrail enabled with Management Events (Read + Write) active prior to executing metrics compilation routines.
* **Wildcard Classifications:** Wildcard permissions (`s3:*`, `ec2:*`) are systematically categorized as `CRITICAL` risk posture exposures regardless of historical logging usage parameters.

---

## References

* [AWS IAM Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
* [AWS CloudTrail Architecture Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
* [Amazon EventBridge Rule Resource Specifications](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule)
* [NIST SP 800-53 — AC-6 Least Privilege Standard Enforcement](https://csrc.mitre.org/publications/detail/sp/800-53/rev-5/final)
* [MITRE ATT&CK Framework — T1078.004 Cloud Accounts Exploitation](https://attack.mitre.org/techniques/T1078/004/)
