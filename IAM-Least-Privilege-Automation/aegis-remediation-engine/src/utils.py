import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def normalize_ip_permissions(raw_permissions):
    """
    Directly addresses parameter differences between CloudTrail event outputs 
    and Boto3 request formats. CloudTrail returns camelCase (e.g., ipProtocol), 
    but boto3.client('ec2').revoke_security_group_ingress requires PascalCase 
    (e.g., IpProtocol).
    """
    sanitized_permissions = []
    
    for perm in raw_permissions:
        #To protect against validation crashes
        clean_perm = {
            'IpProtocol': perm.get('ipProtocol', '-1'),
            'FromPort': perm.get('fromPort') if perm.get('fromPort') is not None else -1,
            'ToPort': perm.get('toPort') if perm.get('toPort') is not None else -1
        }
        

        if 'ipRanges' in perm and 'items' in perm['ipRanges']:
            clean_perm['IpRanges'] = [
                {'CidrIp': item['cidrIp']} 
                for item in perm['ipRanges']['items'] 
                if 'cidrIp' in item
            ]
        else:
            clean_perm['IpRanges'] = []
            
        sanitized_permissions.append(clean_perm)
        
    logger.info(f"[SERIALIZE] Successfully built PascalCase payload: {sanitized_permissions}")
    return sanitized_permissions
