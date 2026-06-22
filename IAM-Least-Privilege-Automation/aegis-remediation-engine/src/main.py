import os
import json
import boto3
import logging
from botocore.exceptions import ClientError
from utils import normalize_ip_permissions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Instantiating base clients for routing configurations
sts_client = boto3.client('sts')
sns_client = boto3.client('sns')

SNS_TELEMETRY_ARN = os.environ.get('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:xxxxxxxxxxxx:Aegis-Alerts')
SECURITY_ROLE_NAME = 'Aegis-Security-Auditor'

def lambda_handler(event, context):
    logger.info(f"[INGEST] Inbound CloudTrail Security Payload: {json.dumps(event)}")
    
    detail = event.get('detail', {})
    event_name = detail.get('eventName')
    target_account = detail.get('AccountId')
    

    request_parameters = detail.get('requestParameters', {})
    group_id = request_parameters.get('groupId')
    ip_permissions_raw = request_parameters.get('ipPermissions', {}).get('items', [])

    if not group_id or not ip_permissions_raw:
        logger.error("[ABORT] Event payload missing target security configurations.")
        return {"status": "SKIPPED", "reason": "Malformed request parameters"}

    # Checking for global zero-trust compliance posture (0.0.0.0/0 exposure check)
    violates_posture = False
    for perm in ip_permissions_raw:
        for item in perm.get('ipRanges', {}).get('items', []):
            if item.get('cidrIp') == '0.0.0.0/0':
                violates_posture = True
                break

    if not violates_posture:
        logger.info("[PASS] Altered rules align with compliance profile bounds.")
        return {"status": "COMPLIANT"}

    logger.warning(f"[DRIFT DETECTED] Public vulnerability opened on group {group_id} in account {target_account}!")

    try:
        # Cross-Account AssumeRole routing handshake
        target_role_arn = f"arn:aws:iam::{target_account}:role/{SECURITY_ROLE_NAME}"
        assumed_session = sts_client.assume_role(
            RoleArn=target_role_arn,
            RoleSessionName="AegisAutoRemediationLoop"
        )
        
        credentials = assumed_session['Credentials']
        
        # Establishing ephemeral client on target account with assumed short-lived tokens
        ec2_target_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        # Invoking utility to format inputs precisely to API specs
        validated_permissions = normalize_ip_permissions(ip_permissions_raw)
        
        # Executing strict rollback infrastructure call
        ec2_target_client.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=validated_permissions
        )
        logger.info(f"[REMEDIATION SUCCESS] Rules revoked on group {group_id}")

        # Distribute state sync event back to centralized alerting dashboard
        alert_msg = f"Aegis Engine rolled back compliance drift on group {group_id} within account {target_account}."
        sns_client.publish(
            TopicArn=SNS_TELEMETRY_ARN,
            Subject=" SECURITY DRIFT AUTOMATICALLY MITIGATED",
            Message=json.dumps({"alert": alert_msg, "remediation_status": "SUCCESS"})
        )
        
        return {"status": "REMEDIATED", "target_group": group_id}

    except ClientError as error:
        logger.error(f"[FATAL FAILURE] Posture engine was blocked: {error}")
        raise error
