---
name: sigma-converter
description: Convert Sigma detection rules to Splunk SPL, Microsoft Sentinel KQL, Elastic Lucene, or CrowdStrike queries, with tuning notes and field mapping guidance. Use this skill whenever the user shares a YAML Sigma rule, asks "convert this to SPL/KQL", mentions SigmaHQ or community detection rules, wants to port detections between SIEMs, or needs to translate a detection concept into a specific query language. Also trigger when the user wants to validate a Sigma rule's logic or improve its field taxonomy before conversion.
---

# Sigma Rule Converter

A detection engineering assistant that converts open-source Sigma rules into SIEM-native queries. Built to help detection engineers port community rules from SigmaHQ into their own environments with tuning notes, false-positive considerations, and MITRE ATT&CK context preserved.

## When to use

Trigger this skill when:

- User pastes a Sigma YAML rule and asks to convert it
- User mentions "Sigma", "SigmaHQ", "sigma-cli", or shares a `.yml` detection
- User asks to port a rule between SIEMs (e.g., "convert my Splunk rule to KQL")
- User wants to write a new detection and mentions the target SIEM
- User asks about field mappings (e.g., "what's CommandLine in KQL?")

## Supported targets

| Target | Backend | Notes |
|--------|---------|-------|
| Splunk SPL | `splunk` | Uses Common Information Model (CIM) where possible |
| Microsoft Sentinel KQL | `kql` | Targets SecurityEvent, DeviceEvents, SigninLogs tables |
| Microsoft Defender XDR | `mde-kql` | Targets DeviceProcessEvents, DeviceNetworkEvents |
| Elastic Lucene | `elastic` | ECS-compliant field names |
| CrowdStrike Falcon | `crowdstrike` | CrowdStrike Query Language |

If the user doesn't specify a target, ask which one before converting. Do not guess.

## Conversion workflow

### Step 1: Parse the Sigma rule

Extract these sections and confirm they are present:

- `title`, `id`, `status`, `description`
- `logsource` — category, product, service
- `detection` — selection blocks and `condition`
- `falsepositives` — preserve in output comments
- `tags` — especially `attack.t*` for MITRE mapping
- `level` — severity hint

If the YAML is malformed, call out the exact line and ask for a fix rather than guessing.

### Step 2: Resolve the logsource to the target's table/index

Use this mapping as the default starting point. Adjust based on the user's environment if they provide context:

| Sigma logsource | Splunk | Sentinel KQL | MDE KQL | Elastic |
|-----------------|--------|--------------|---------|---------|
| `product: windows, category: process_creation` | `index=windows sourcetype=WinEventLog:Security EventCode=4688` OR Sysmon `EventCode=1` | `SecurityEvent \| where EventID == 4688` | `DeviceProcessEvents` | `event.category:process AND event.type:start` |
| `product: windows, category: network_connection` | Sysmon `EventCode=3` | `DeviceNetworkEvents` | `DeviceNetworkEvents` | `event.category:network` |
| `product: windows, category: file_event` | Sysmon `EventCode=11` | `DeviceFileEvents` | `DeviceFileEvents` | `event.category:file` |
| `product: linux, category: process_creation` | `sourcetype=linux:audit` | `Syslog` or custom table | N/A | `event.category:process` |
| `product: azure, service: signinlogs` | Azure AD TA | `SigninLogs` | N/A | Azure integration |
| `product: aws, service: cloudtrail` | `sourcetype=aws:cloudtrail` | `AWSCloudTrail` | N/A | `event.dataset:aws.cloudtrail` |

### Step 3: Translate detection logic

Handle these Sigma modifiers correctly:

| Sigma | Splunk | KQL | Elastic |
|-------|--------|-----|---------|
| `field: value` | `field="value"` | `field == "value"` | `field:"value"` |
| `field\|contains: x` | `field="*x*"` | `field contains "x"` | `field:*x*` |
| `field\|startswith: x` | `field="x*"` | `field startswith "x"` | `field:x*` |
| `field\|endswith: x` | `field="*x"` | `field endswith "x"` | `field:*x` |
| `field\|re: pattern` | `\| regex field="pattern"` | `field matches regex "pattern"` | `field:/pattern/` |
| List of values | `field IN ("a","b")` | `field in ("a","b")` | `field:(a OR b)` |
| `condition: selection1 and selection2` | Combine with AND | Combine with `and` | Combine with AND |
| `condition: 1 of them` | Combine with OR | Combine with `or` | Combine with OR |
| `condition: selection and not filter` | Add `NOT (...)` | `and not (...)` | `AND NOT (...)` |

### Step 4: Map fields to the target schema

Sigma uses generic Windows event field names. Map them correctly:

| Sigma field | Splunk (CIM/Sysmon) | Sentinel KQL | MDE KQL |
|-------------|---------------------|--------------|---------|
| `Image` | `process` or `Image` | `NewProcessName` | `FileName` / `FolderPath` |
| `CommandLine` | `CommandLine` | `CommandLine` | `ProcessCommandLine` |
| `ParentImage` | `parent_process` | `ParentProcessName` | `InitiatingProcessFileName` |
| `ParentCommandLine` | `parent_process_cmd` | N/A (not logged by default) | `InitiatingProcessCommandLine` |
| `User` | `user` | `SubjectUserName` | `AccountName` |
| `TargetFilename` | `TargetFilename` (Sysmon 11) | `TargetFileName` | `FolderPath` |
| `DestinationIp` | `dest_ip` | `DestinationIP` | `RemoteIP` |
| `DestinationHostname` | `dest_host` | `RemoteUrl` | `RemoteUrl` |

If a field has no direct equivalent, flag it in a comment and suggest the closest match.

### Step 5: Add tuning context

Every converted rule must include:

1. A header comment with: source rule title, Sigma ID, MITRE technique IDs
2. The `falsepositives` section from the original, translated into tuning suggestions
3. A suggested time window and aggregation if the original is event-based
4. A confidence note if any field mapping was approximate

## Output format

ALWAYS return this exact structure:

````
# Converted Rule: <original title>

**Source Sigma ID:** <uuid>
**Target:** <Splunk SPL | Sentinel KQL | MDE KQL | Elastic | CrowdStrike>
**MITRE ATT&CK:** <T-IDs from tags>
**Severity:** <from Sigma level>

## Query

```<spl|kql|lucene>
<the converted query>
```

## Field Mapping Notes
- <any approximations or caveats>

## Tuning Suggestions
- <from Sigma falsepositives, adapted>
- <suggested exclusions based on common enterprise noise>

## Validation Checklist
- [ ] Logsource table exists in target environment
- [ ] Fields confirmed present (run a `search ... | head 1` first)
- [ ] Time window appropriate for rule type
- [ ] No high-cardinality wildcards causing performance issues
````

## Script support

`scripts/sigma_parse.py` validates Sigma YAML syntax and extracts key fields:

```bash
python scripts/sigma_parse.py rule.yml
```

This is useful for sanity-checking a rule before conversion. It does not perform the conversion — that requires Claude's reasoning for field mapping and logic translation.

## Common pitfalls

- **Case sensitivity**: Sigma is case-insensitive by default. KQL is case-sensitive. Always use `=~` (case-insensitive equals) in KQL for strings, unless the user specifies otherwise.
- **Wildcard position**: `field|contains: x` in Sigma is `*x*` in Splunk, but Splunk struggles with leading wildcards on indexed fields. Flag this as a performance concern.
- **Null/missing values**: Sigma's `field: null` means the field is absent. In KQL use `isempty(field)`, in Splunk use `NOT field=*`.
- **MDE vs Sentinel KQL**: Same language, different tables. Don't mix `SecurityEvent` (Sentinel) with `DeviceProcessEvents` (MDE) in the same query.
- **Regex flavors**: Sigma uses PCRE. Splunk uses PCRE2. KQL uses RE2 (no backreferences, no lookahead). Call out any features that won't translate.

## What NOT to do

- Do not convert without confirming the target platform
- Do not silently drop conditions you don't understand — flag them
- Do not use `*` as a standalone wildcard in Splunk queries (matches everything, kills performance)
- Do not skip the tuning section — a rule without tuning notes is not production-ready
