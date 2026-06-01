Continuous Identity Guarding
Extension of the IAM Least Privilege Automation project. Converts the one-time analysis into a fully automated continuous audit capability.

What Was Added

Ghost role detection — flags roles with zero activity older than 90 days
AWS Lambda function replacing the manual Kali script
EventBridge scheduler triggering every 30 days automatically
SNS email report delivered to inbox after every run
Lambda role self-remediation — audit infrastructure scoped to least-privilege
Service Control Policy to prevent wildcard permissions at organization level

Architecture
EventBridge Scheduler (every 30 days)
        ↓
Lambda — iam-audit-lambda (Python 3.12, arm64)
        ↓
IAM + CloudTrail analysis
        ↓
SNS Topic
        ↓
Email report


**References

AWS Lambda Documentation
AWS EventBridge Scheduler
AWS SNS Documentation
NIST SP 800-53 AC-6 Least Privilege**
