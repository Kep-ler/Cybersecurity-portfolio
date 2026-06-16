# Project Aegis: Boto3 API Reference

## IAM Module

| Action | boto3 Method | Purpose |
|---|---|---|
| List all roles | `iam.get_paginator("list_roles")` | Enumerate all IAM roles excluding service-linked |
| Get attached policies | `iam.get_paginator("list_attached_role_policies")` | Get managed policies per role |
| Get inline policies | `iam.get_paginator("list_role_policies")` | Get inline policies per role |
| Read policy document | `iam.get_policy_version()` | Retrieve actual policy JSON |
| Read inline policy | `iam.get_role_policy()` | Retrieve inline policy document |
| Read trust policy | `role["AssumeRolePolicyDocument"]` | Returned directly in list_roles response |

## CloudTrail Module

| Action | boto3 Method | Purpose |
|---|---|---|
| Query API activity | `ct.get_paginator("lookup_events")` | Find all API calls by a role ARN in 90-day window |

## S3 Module

| Action | boto3 Method | Purpose |
|---|---|---|
| List all buckets | `s3.list_buckets()` | Enumerate all S3 buckets in account |
| Check public access | `s3.get_public_access_block(Bucket=name)` | Returns four Block Public Access settings |
| Check encryption | `s3.get_bucket_encryption(Bucket=name)` | Returns default encryption config, throws exception if not set |

## EC2 Module

| Action | boto3 Method | Purpose |
|---|---|---|
| List security groups | `ec2.describe_security_groups()` | Returns all security groups with inbound rules |

## SNS Module

| Action | boto3 Method | Purpose |
|---|---|---|
| Send report | `sns.publish(TopicArn, Subject, Message)` | Publishes formatted report to SNS topic for email delivery |

## Notes

- All IAM and CloudTrail calls use pagination via `get_paginator` to handle large result sets
- S3 encryption check uses exception handling as the signal — if `get_bucket_encryption` throws, encryption is not configured
- EC2 `describe_security_groups` returns all groups without pagination in most accounts — add pagination for accounts with 100+ security groups
- Trust policy is embedded in the `list_roles` response — no additional API call needed
