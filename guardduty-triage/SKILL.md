---
name: guardduty-triage
description: Triage AWS GuardDuty findings with MITRE ATT&CK mapping, severity reassessment based on asset context, and SOAR-ready remediation. Use this skill whenever the user shares GuardDuty JSON, asks "what does this finding mean?", needs to assess if a finding is a true positive, asks about AWS cloud threats, or wants to convert a GuardDuty finding into an incident response action plan. Also trigger for questions about GuardDuty finding types, IAM compromise detection, crypto-mining findings, or cloud IR workflows.
---

# GuardDuty Finding Triage

A cloud-native sibling to the alert-triage skill, specialized for AWS GuardDuty. Turns raw GuardDuty finding JSON into a structured incident verdict with MITRE ATT&CK mapping, reassessed severity based on account/resource context, and concrete remediation steps.

## When to use

Trigger on any of:

- User pastes GuardDuty finding JSON (from Security Hub, EventBridge, or `aws guardduty get-findings`)
- User mentions a GuardDuty finding type (e.g., "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B")
- Questions about AWS API abuse, crypto-mining EC2 findings, or suspicious IAM activity
- User asks to convert a GuardDuty finding into a playbook or ticket
- Cloud incident response discussions involving GuardDuty signal

## Input types supported

1. **Single finding**: raw JSON from GuardDuty API or EventBridge event
2. **Security Hub finding**: the AWS Security Finding Format (ASFF) wrapper around a GuardDuty finding
3. **Batch**: JSON array of findings from `aws guardduty get-findings --finding-ids ...`

If the schema is ambiguous, ask the user which source the JSON came from.

## Triage workflow

### Step 1: Parse and normalize

Extract these fields regardless of wrapper format:

- `finding_type` — the full dotted string, e.g. `Recon:IAMUser/UserPermissions`
- `severity` — GuardDuty's 1.0–8.9 float, mapped to Low/Medium/High
- `service` — which AWS service generated the signal (EC2, IAM, S3, etc.)
- `resource` — affected resource (instanceId, accessKeyDetails, s3BucketDetails)
- `action` — what the actor did (AwsApiCall, NetworkConnection, PortProbe, DnsRequest)
- `evidence` — API name, remote IP, user agent, timestamps
- `account_id` — where it fired
- `region` — AWS region

If a field is missing, mark it `null` rather than guessing.

### Step 2: Classify by finding family

GuardDuty findings cluster into these families. Use the family to anchor MITRE mapping and response priority:

| Family | Prefix examples | What to look for |
|--------|-----------------|------------------|
| **Reconnaissance** | `Recon:*`, `PenTest:*` | Port scanning, unusual API enumeration, IAM permission discovery |
| **Unauthorized Access** | `UnauthorizedAccess:*` | Console login from Tor/VPN, credential use from new geo, instance credential exfil |
| **Policy Violation** | `Policy:*` | Root account usage, S3 public config changes, password policy violations |
| **Stealth** | `Stealth:*` | CloudTrail disabled, logging modified, S3 server access logs disabled |
| **Crypto-mining** | `CryptoCurrency:*` | Known crypto pool domain DNS, mining pool IP traffic |
| **Backdoor** | `Backdoor:*` | C2 domain DNS, suspicious outbound TCP from EC2 |
| **Malware** | `Trojan:*` | Known malware IOC hits, RDP brute force |
| **Exfiltration** | `Exfiltration:*` | Anomalous S3 access, Macie-enhanced signals |
| **Impact** | `Impact:*` | EC2 DDoS launch, S3 object deletion anomalies |
| **Credential Access** | `CredentialAccess:*` | Anomalous AssumeRole, credential compromise signals |
| **Execution** | `Execution:*` | EKS runtime detections, unusual Lambda behavior |

### Step 3: MITRE ATT&CK mapping

Map the finding to ATT&CK for Cloud. Common mappings:

| GuardDuty prefix | Tactic | Technique |
|------------------|--------|-----------|
| `Recon:IAMUser/UserPermissions` | TA0007 Discovery | T1087.004 Cloud Account Discovery |
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | TA0001 Initial Access | T1078.004 Valid Accounts: Cloud |
| `UnauthorizedAccess:EC2/TorIPCaller` | TA0011 C2 | T1090.003 Multi-hop Proxy |
| `Policy:IAMUser/RootCredentialUsage` | TA0004 Privilege Escalation | T1078.004 Valid Accounts: Cloud |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | TA0005 Defense Evasion | T1562.008 Disable Cloud Logs |
| `CryptoCurrency:EC2/BitcoinTool.B` | TA0040 Impact | T1496 Resource Hijacking |
| `Backdoor:EC2/C&CActivity.B!DNS` | TA0011 C2 | T1071.004 DNS |
| `Trojan:EC2/DropPoint!DNS` | TA0010 Exfiltration | T1567 Exfiltration Over Web Service |
| `Exfiltration:S3/AnomalousBehavior` | TA0010 Exfiltration | T1537 Transfer Data to Cloud Account |
| `Impact:EC2/AbusedDomainRequest.Reputation` | TA0040 Impact | T1498 Network DoS |
| `CredentialAccess:IAMUser/AnomalousBehavior` | TA0006 Credential Access | T1552.005 Cloud Instance Metadata |
| `Execution:EKS/AnomalousBehavior` | TA0002 Execution | T1609 Container Admin Command |

If the finding is new or unlisted, map by observed behavior, not by name.

### Step 4: Severity reassessment

GuardDuty severity is useful but context-blind. Reassess using:

| Factor | Weight |
|--------|--------|
| Account tier (prod vs dev vs sandbox) | High |
| Resource criticality (crown-jewel S3, prod DB, CI/CD role) | High |
| Actor identity (human, service account, wildcard role) | Medium |
| IP reputation (known-bad, Tor, datacenter, corporate) | Medium |
| Time-of-day (business hours vs off-hours) | Low |
| Repetition (first-time vs recurring) | Medium |
| Adjacent findings (part of a kill chain?) | High |

Output: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`. Always explain the delta from GuardDuty's original score.

### Step 5: Verdict

Choose exactly one:

- **TRUE POSITIVE — Confirmed malicious** → execute IR playbook, preserve evidence
- **LIKELY TRUE POSITIVE — Investigate** → pull CloudTrail, interview IAM principal owner
- **BENIGN TRUE POSITIVE — Expected** → document, suppress finding type for this resource
- **FALSE POSITIVE** → close + create suppression rule
- **INSUFFICIENT DATA** → list the specific CloudTrail/VPC Flow queries needed

### Step 6: Recommended actions

Every action must be concrete and runnable. Examples:

- `aws guardduty update-findings-feedback --finding-ids ... --feedback USEFUL`
- `aws ec2 stop-instances --instance-ids i-abc123` (contain)
- `aws iam delete-access-key --access-key-id AKIA... --user-name compromised-user`
- "Search CloudTrail for AssumeRole by sessionIssuer.arn={} in last 24h"
- "Block IP at security group / NACL / WAF" (specify which layer)

## Output format

ALWAYS return this exact structure:

````
# GuardDuty Triage Report

**Finding ID:** <id>
**Type:** <finding_type>
**Time:** <UTC>
**Account / Region:** <account_id> / <region>
**Affected resource:** <resource ARN or id>

## Summary
<2-3 sentence plain-English explanation of what GuardDuty observed>

## MITRE ATT&CK
- Tactic: <ID + name>
- Technique: <ID + name>
- Confidence: <High|Medium|Low>

## Severity Assessment
- GuardDuty score: <e.g., 5.0 / Medium>
- Analyst-assessed: <reassessed>
- Rationale: <why>

## Verdict
<one of five>

## Evidence
- Actor: <IAM principal or IP>
- Action: <API / network event>
- Target: <resource>
- Indicators: <IPs, domains, ASNs, user agents>

## Recommended Actions
1. <concrete command or query>
2. ...

## Investigation Queries
```sql
-- CloudTrail via Athena example
SELECT eventTime, eventName, sourceIPAddress, userIdentity.arn
FROM cloudtrail_logs
WHERE eventTime > '2026-04-19T00:00:00Z'
  AND userIdentity.accessKeyId = '<key>'
ORDER BY eventTime DESC;
```

## SOAR Payload
```json
{
  "finding_id": "...",
  "verdict": "TRUE_POSITIVE",
  "severity": "HIGH",
  "mitre": {"tactic": "TA0001", "technique": "T1078.004"},
  "actions": ["disable_access_key", "notify_principal_owner"],
  "confidence": 0.85
}
```

## Suppression Rule (if false positive)
```json
{
  "Criterion": {
    "type": {"Eq": ["<finding_type>"]},
    "resource.instanceDetails.tags.key": {"Eq": ["environment:dev"]}
  }
}
```
````

## Script support

`scripts/fetch_findings.py` wraps `aws guardduty list-findings` + `get-findings` to pull recent findings into a JSONL file ready for batch review:

```bash
python scripts/fetch_findings.py --region ap-southeast-1 --max 50 --output findings.jsonl
```

Requires AWS CLI credentials. The script fetches and normalizes — it does not perform triage itself (that's Claude's reasoning above).

## Edge cases

- **Archived findings**: GuardDuty archives after 90 days. If `"archived": true`, note that evidence gathering may be limited.
- **Multi-region exposure**: always check the `region` field. A finding in us-east-1 for an ap-southeast-1 primary account is a red flag on its own.
- **EKS/Runtime Monitoring**: these have richer container context (pod, namespace, image). Include in the report.
- **Sample findings**: `aws guardduty create-sample-findings` produces synthetic findings. Check `"service.additionalInfo.sample": true` before acting.
