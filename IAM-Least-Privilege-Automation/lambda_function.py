import boto3
import json
from datetime import datetime, timedelta, timezone

DAYS_TO_ANALYZE = 90
REGION = "us-east-1"
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:xxxxxxxxxx:iam-audit-report-topic"
TRUSTED_ACCOUNTS = ["xxxxxxxxxxxxxx"]

def get_all_iam_roles(iam_client):
    roles = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            if "aws-service-role" not in role["Path"]:
                roles.append({
                    "RoleName": role["RoleName"],
                    "RoleArn": role["Arn"],
                    "CreateDate": role["CreateDate"].strftime("%Y-%m-%d"),
                    "AssumeRolePolicyDocument": role["AssumeRolePolicyDocument"]
                })
    return roles

def get_role_policies(iam_client, role_name):
    permissions = set()
    paginator = iam_client.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy in page["AttachedPolicies"]:
            policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = policy_detail["Policy"]["DefaultVersionId"]
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=version_id
            )
            document = policy_version["PolicyVersion"]["Document"]
            for statement in document.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    permissions.update(actions)
    return permissions

def get_cloudtrail_activity(ct_client, role_arn):
    used_actions = set()
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=DAYS_TO_ANALYZE)
    try:
        paginator = ct_client.get_paginator("lookup_events")
        pages = paginator.paginate(
            LookupAttributes=[{
                "AttributeKey": "ResourceARN",
                "AttributeValue": role_arn
            }],
            StartTime=start_time,
            EndTime=end_time
        )
        for page in pages:
            for event in page.get("Events", []):
                event_name = event.get("EventName", "")
                event_source = event.get("EventSource", "").replace(".amazonaws.com", "")
                if event_name and event_source:
                    used_actions.add(f"{event_source}:{event_name}")
    except Exception as e:
        print(f"CloudTrail error: {e}")
    return used_actions

def check_cross_account_trust(roles):
    findings = []
    for role in roles:
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        for statement in trust_doc.get("Statement", []):
            principal = statement.get("Principal", {})
            principals = []
            if isinstance(principal, str):
                principals = [principal]
            elif isinstance(principal, dict):
                for v in principal.values():
                    if isinstance(v, list):
                        principals.extend(v)
                    else:
                        principals.append(v)
            for p in principals:
                if p == "*":
                    findings.append({
                        "RoleName": role["RoleName"],
                        "Issue": "Trust policy allows public assumption via *",
                        "Principal": p,
                        "Severity": "CRITICAL"
                    })
                elif "arn:aws:iam::" in p:
                    account_id = p.split(":")[4]
                    if account_id not in TRUSTED_ACCOUNTS:
                        findings.append({
                            "RoleName": role["RoleName"],
                            "Issue": f"Trust policy allows external account: {account_id}",
                            "Principal": p,
                            "Severity": "HIGH"
                        })
    return findings

def check_s3_posture(s3_client):
    findings = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            public_access_issue = False
            encryption_issue = False
            try:
                pab = s3_client.get_bucket_public_access_block(Bucket=name)
                config = pab.get("PublicAccessBlockConfiguration", {})
                block_public_acls = config.get("BlockPublicAcls", False)
                ignore_public_acls = config.get("IgnorePublicAcls", False)
                block_public_policy = config.get("BlockPublicPolicy", False)
                restrict_public_buckets = config.get("RestrictPublicBuckets", False)
                if not all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                    public_access_issue = True
            except Exception:
                public_access_issue = True
            try:
                s3_client.get_bucket_encryption(Bucket=name)
            except Exception:
                encryption_issue = True
            if public_access_issue or encryption_issue:
                issues = []
                if public_access_issue:
                    issues.append("Block Public Access not fully enabled")
                if encryption_issue:
                    issues.append("Default encryption not configured")
                findings.append({
                    "BucketName": name,
                    "Issues": issues,
                    "Severity": "CRITICAL" if public_access_issue else "HIGH"
                })
    except Exception as e:
        print(f"S3 scan error: {e}")
    return findings

def check_security_groups(ec2_client):
    findings = []
    try:
        response = ec2_client.describe_security_groups()
        for sg in response["SecurityGroups"]:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        if from_port <= 22 <= to_port:
                            findings.append({
                                "SecurityGroupId": sg["GroupId"],
                                "SecurityGroupName": sg["GroupName"],
                                "Issue": "SSH port 22 open to 0.0.0.0/0",
                                "Severity": "CRITICAL"
                            })
                        if from_port <= 3389 <= to_port:
                            findings.append({
                                "SecurityGroupId": sg["GroupId"],
                                "SecurityGroupName": sg["GroupName"],
                                "Issue": "RDP port 3389 open to 0.0.0.0/0",
                                "Severity": "CRITICAL"
                            })
    except Exception as e:
        print(f"Security group scan error: {e}")
    return findings

def lambda_handler(event, context):
    iam = boto3.client("iam", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)
    sns = boto3.client("sns", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)

    roles = get_all_iam_roles(iam)
    iam_report = []

    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["RoleArn"]
        granted = get_role_policies(iam, role_name)
        used = get_cloudtrail_activity(ct, role_arn)
        unused = granted - used
        wildcards = [p for p in granted if "*" in p]
        non_wildcard_unused = [p for p in unused if "*" not in p]

        risk_level = "LOW"
        if len(wildcards) > 0:
            risk_level = "CRITICAL"
        elif len(non_wildcard_unused) > len(granted) * 0.7:
            risk_level = "HIGH"
        elif len(non_wildcard_unused) > len(granted) * 0.3:
            risk_level = "MEDIUM"

        created = datetime.strptime(role["CreateDate"], "%Y-%m-%d")
        today = datetime.now()
        role_age_days = (today - created).days
        ghost = role_age_days > 90 and len(used) == 0

        iam_report.append({
            "RoleName": role_name,
            "RoleAgeDays": role_age_days,
            "GrantedPermissions": len(granted),
            "UsedPermissions": len(used),
            "UnusedPermissions": len(non_wildcard_unused),
            "WildcardPermissions": len(wildcards),
            "GhostRole": ghost,
            "RiskLevel": risk_level
        })

    trust_findings = check_cross_account_trust(roles)
    s3_findings = check_s3_posture(s3)
    sg_findings = check_security_groups(ec2)

    critical_iam = [r for r in iam_report if r["RiskLevel"] == "CRITICAL"]
    high_iam = [r for r in iam_report if r["RiskLevel"] == "HIGH"]
    ghosts = [r for r in iam_report if r["GhostRole"]]
    critical_trust = [f for f in trust_findings if f["Severity"] == "CRITICAL"]
    high_trust = [f for f in trust_findings if f["Severity"] == "HIGH"]
    critical_s3 = [f for f in s3_findings if f["Severity"] == "CRITICAL"]
    high_s3 = [f for f in s3_findings if f["Severity"] == "HIGH"]
    critical_sg = [f for f in sg_findings if f["Severity"] == "CRITICAL"]

    total_critical = len(critical_iam) + len(critical_trust) + len(critical_s3) + len(critical_sg)
    total_high = len(high_iam) + len(high_trust) + len(high_s3)

    message = f"""
CLOUD SECURITY POSTURE MANAGEMENT REPORT
Project Aegis: Multi-Service Hardening
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M UTC")}
Account: AWS Sandbox
{"=" * 60}

EXECUTIVE SUMMARY
-----------------
Total Critical Findings : {total_critical}
Total High Findings     : {total_high}
Ghost Roles Detected    : {len(ghosts)}

{"=" * 60}
MODULE 1: IAM PRIVILEGE ANALYSIS
---------------------------------
Roles Analyzed       : {len(iam_report)}
Critical (Wildcards) : {len(critical_iam)}
High (Unused)        : {len(high_iam)}
Ghost Roles          : {len(ghosts)}
"""
    for r in critical_iam:
        message += f"\n  CRITICAL: {r['RoleName']} | {r['WildcardPermissions']} wildcards | Age: {r['RoleAgeDays']} days"
    for r in high_iam:
        message += f"\n  HIGH: {r['RoleName']} | {r['UnusedPermissions']} unused permissions"
    for g in ghosts:
        message += f"\n  GHOST: {g['RoleName']} | Age: {g['RoleAgeDays']} days | Decommission recommended"

    message += f"""

{"=" * 60}
MODULE 2: CROSS-ACCOUNT TRUST ANALYSIS
----------------------------------------
Critical Trust Issues : {len(critical_trust)}
High Trust Issues     : {len(high_trust)}
"""
    if trust_findings:
        for f in trust_findings:
            message += f"\n  {f['Severity']}: {f['RoleName']} | {f['Issue']}"
    else:
        message += "\n  No cross-account trust issues detected"

    message += f"""

{"=" * 60}
MODULE 3: STORAGE PERIMETER ANALYSIS
--------------------------------------
Buckets Scanned      : {len(buckets) if 'buckets' in dir() else 'N/A'}
Critical S3 Findings : {len(critical_s3)}
High S3 Findings     : {len(high_s3)}
"""
    if s3_findings:
        for f in s3_findings:
            message += f"\n  {f['Severity']}: {f['BucketName']} | {', '.join(f['Issues'])}"
    else:
        message += "\n  All buckets properly configured"

    message += f"""

{"=" * 60}
MODULE 4: NETWORK INGRESS ANALYSIS
------------------------------------
Critical SG Findings : {len(critical_sg)}
"""
    if sg_findings:
        for f in sg_findings:
            message += f"\n  {f['Severity']}: {f['SecurityGroupName']} ({f['SecurityGroupId']}) | {f['Issue']}"
    else:
        message += "\n  No open administrative ports detected"

    message += f"""

{"=" * 60}
ACTION REQUIRED
---------------
CRITICAL: Immediate remediation required
HIGH: Review and remediate within 7 days
GHOST ROLES: Confirm no legitimate use then decommission

This is an automated report from Project Aegis.
Do not reply to this message.
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"CSPM Report: {total_critical} Critical, {total_high} High Findings",
        Message=message
    )

    print(f"CSPM report published. Critical: {total_critical}, High: {total_high}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "TotalCritical": total_critical,
            "TotalHigh": total_high,
            "GhostRoles": len(ghosts),
            "S3Findings": len(s3_findings),
            "SGFindings": len(sg_findings),
            "TrustFindings": len(trust_findings)
        })
    }
