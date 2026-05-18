IAM Least Privilege Automation
Automated detection and remediation of over-privileged IAM roles using CloudTrail log analysis, a custom Python script, and Terraform infrastructure-as-code.

Overview
This project implements a least-privilege automation pipeline for AWS IAM. It analyzes 90 days of CloudTrail activity to identify permissions granted to IAM roles that were never exercised, classifies each role by risk level, and applies Terraform-based remediation to replace broad policies with narrow, task-specific ones.
Success metric: Reduce High and Critical IAM Access Analyzer findings by 80% without breaking application functionality. Achieved: 96% reduction.

Stack

AWS IAM Access Analyzer (Principal Analysis — Unused Access)
AWS CloudTrail
Python 3 + boto3
Terraform v1.x
AWS CLI v2
Kali Linux (aarch64)


How It Works
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

Results
MetricBeforeAfterReductionPermissions granted67396%Wildcard permissions80100%Risk levelCRITICALHIGHReducedAnalyzer findings (High/Critical)—0Target met

Project Structure
iam-analyzer/
├── analyze_iam.py          # CloudTrail analysis script
└── terraform/
    ├── provider.tf         # AWS provider configuration
    ├── main.tf             # IAM policy remediation resources
    └── terraform.tfstate   # Terraform state (gitignored)

Usage
1. Install dependencies
bashpip3 install boto3 --break-system-packages
2. Configure AWS CLI
bashaws configure
aws sts get-caller-identity
3. Run analysis
bashpython3 analyze_iam.py
4. Detach existing broad policies
bashaws iam detach-role-policy \
  --role-name [role-name] \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
5. Apply Terraform remediation
bashcd terraform/
terraform init
terraform plan
terraform apply
6. Validate
bashpython3 analyze_iam.py
Compare output against pre-remediation report. Verify IAM Access Analyzer shows 0 High/Critical findings.

Key Notes

Requires CloudTrail enabled with Management Events (Read + Write) before analysis
IAM Access Analyzer Unused Access type is required — the free External Access type solves a different problem
Resources created outside Terraform must be detached via CLI before apply to avoid state conflicts
Wildcard permissions (s3:*, ec2:*) are classified CRITICAL regardless of usage
Script is production-ready — extend to Lambda for continuous scheduled analysis


References

AWS IAM Access Analyzer
AWS CloudTrail
Terraform AWS Provider
NIST SP 800-53 — AC-6 Least Privilege
MITRE ATT&CK T1078.004
