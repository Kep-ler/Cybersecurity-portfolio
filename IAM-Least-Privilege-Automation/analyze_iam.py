import json
import boto3
from datetime import datetime, timedelta, timezone

DAYS_TO_ANALYZE = 90
AWS_REGION = "us-east-1"

def get_all_iam_roles(iam_client):
    print("\n[*] Fetching all IAM roles...")
    roles = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            if "aws-service-role" not in role["Path"]:
                roles.append({
                    "RoleName": role["RoleName"],
                    "RoleArn": role["Arn"],
                    "CreateDate": role["CreateDate"].strftime("%Y-%m-%d")
                })
    print(f"    Found {len(roles)} roles")
    return roles

def get_role_permissions(iam_client, role_name):
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
    print(f"    [*] Querying CloudTrail...")
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
        print(f"    [!] CloudTrail error: {e}")
    return used_actions

def analyze_roles():
    print("=" * 60)
    print("  IAM Unused Permission Analyzer")
    print(f"  Analysis window: Last {DAYS_TO_ANALYZE} days")
    print(f"  Region: {AWS_REGION}")
    print("=" * 60)

    iam = boto3.client("iam", region_name=AWS_REGION)
    ct = boto3.client("cloudtrail", region_name=AWS_REGION)

    roles = get_all_iam_roles(iam)
    report = []

    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["RoleArn"]
        print(f"\n[*] Analyzing role: {role_name}")

        granted = get_role_permissions(iam, role_name)
        used = get_cloudtrail_activity(ct, role_arn)
        unused = granted - used

        wildcards = [p for p in granted if "*" in p]
        non_wildcard_unused = [p for p in unused if "*" not in p]

        if wildcards:
            risk = "CRITICAL"
        elif len(non_wildcard_unused) > len(granted) * 0.7:
            risk = "HIGH"
        elif len(non_wildcard_unused) > len(granted) * 0.3:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print(f"    Granted         : {len(granted)}")
        print(f"    Used (90 days)  : {len(used)}")
        print(f"    Unused          : {len(non_wildcard_unused)}")
        print(f"    Wildcards       : {len(wildcards)}")
        print(f"    Risk Level      : {risk}")

        report.append({
            "RoleName": role_name,
            "RoleArn": role_arn,
            "CreatedDate": role["CreateDate"],
            "GrantedPermissions": len(granted),
            "UsedPermissions": len(used),
            "UnusedPermissions": len(non_wildcard_unused),
            "WildcardPermissions": wildcards,
            "UnusedList": sorted(non_wildcard_unused),
            "RiskLevel": risk
        })

    print("\n" + "=" * 60)
    print("  ANALYSIS REPORT")
    print("=" * 60)

    for r in sorted(report, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["RiskLevel"])):
        print(f"\nRole: {r['RoleName']}")
        print(f"  Risk Level      : {r['RiskLevel']}")
        print(f"  Granted         : {r['GrantedPermissions']}")
        print(f"  Used (90 days)  : {r['UsedPermissions']}")
        print(f"  Unused          : {r['UnusedPermissions']}")
        if r["WildcardPermissions"]:
            print(f"  Wildcards       : {r['WildcardPermissions']}")
        if r["UnusedList"]:
            print(f"  Unused actions  : {r['UnusedList'][:10]}")

    output_file = f"iam_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[✓] Report saved to: {output_file}")

if __name__ == "__main__":
    analyze_roles()
