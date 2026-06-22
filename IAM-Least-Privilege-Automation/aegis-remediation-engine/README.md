# Real-Time Event-Driven Cross-Account IAM Remediation Engine

## Technical Architecture Overview
Project Aegis is a decoupled, multi-account automation architecture designed to eliminate drift latency entirely. Instead of scanning configurations on scheduled cron routines, this design tracks configuration mutations in real-time by treating account states as a continuously streamed event data pipeline.

### Cross-Account Infrastructure Flow Tree
1. **WORKLOAD ACCOUNT:** A manual engineering change modifies an EC2 security group rule to include `0.0.0.0/0`.
2. **CLOUDTRAIL ENGINE:** Captures the structural API management call and fires an event configuration payload out-of-band.
3. **EVENTBRIDGE RULE:** Intercepts the raw `ec2.amazonaws.com` payload on the default bus, filters it against the structural regex match defined in `config/event-pattern.json`, and streams it across account lines to the core hub.
4. **CENTRAL LAMBDA CORE:** Receives the event object, handles parameter casing compilation disparities, assumes an execution identity in the target environment via an `sts:AssumeRole` configuration handshake, and invokes a strict configuration rollback (`revoke_security_group_ingress`).
5. **TELEMETRY OUTFLOW:** Issues a structured JSON metric payload down an Amazon SNS tracking topic to notify the active engineering team.

---

## Code Base Mechanics & Engineering Obstacles Resolved

### 1. Handling camelCase vs. PascalCase Object Structure Incompatibilities
* **The Structural Failure:** Initial manual integration triggers produced hard SDK system tracebacks. CloudTrail event properties route parameters natively as nested camelCase fields (e.g., `ipProtocol`, `fromPort`), whereas the underlying Python Boto3 interface layers explicitly demand structured PascalCase input variables (`IpProtocol`, `FromPort`). Passing raw event configurations directly resulted in an explicit `ParamValidation` runtime exception.
* **The Resolution:** Abstracted payload serialization workflows out of the primary operational code layer. Built a dedicated validation parser map inside `src/utils.py` that loops through raw nested objects, verifies explicit dictionary value presence, and transforms parameter keys into the explicit formats demanded by the backend client APIs before initialization.

### 2. Workstation Workspace Segregation & Token Validation Profiles
* **The Local Bottleneck:** Local functional integration tracking executed directly inside a development environment terminal (`kepler@kali`) produced authorization failures. The infrastructure constraints intentionally blocked manual testing profiles from assuming cross-account processing targets directly.
* **The Resolution:** Upgraded local manual debugging methods to align with Zero-Trust parameters. Instead of manually expanding permissions on human operator credentials or setting up persistent local access keys, the validation architecture was confirmed by feeding simulated test objects securely into the cloud environment core (`aws lambda invoke`), ensuring local workspaces remained separate from core cloud resources.

---

## Deployment Validation & Performance Metrics
The execution payload tracing block demonstrates an instant automated mitigation loop when processing live rule modifications:

```text
START RequestId: 166ac039-c316-42fc-86e8-7b631179487c Version: $LATEST
[INFO] [INGEST] Inbound CloudTrail Security Payload: {"source": "aws.ec2", "detail-type": "AWS API Call via CloudTrail"...}
[WARN] [DRIFT DETECTED] Public vulnerability opened on group sg-0a123b45678cd90ef in account 222222222222!
[INFO] [SERIALIZE] Successfully built PascalCase payload: [{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
[INFO] [REMEDIATION SUCCESS] Rules revoked on group sg-0a123b45678cd90ef
END RequestId: 166ac039-c316-42fc-86e8-7b631179487c
REPORT RequestId: 166ac039-c316-42fc-86e8-7b631179487c  Duration: 337.38 ms  Billed Duration: 338 ms  Memory Used: 103 MB
