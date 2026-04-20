---
name: alert-triage
description: Triage SIEM/EDR security alerts with MITRE ATT&CK mapping, severity reassessment, and SOAR-ready action recommendations. Use this skill whenever the user pastes raw alert JSON, asks to "triage this alert", mentions Defender/Splunk/Sentinel/CrowdStrike/XSOAR alerts, asks what an alert means, wants to know if something is a true positive, or needs a structured SOC analyst verdict on suspicious activity. Trigger even if the word "triage" is not used — any request that looks like alert analysis, IOC evaluation, or "is this malicious?" qualifies.
---

# Alert Triage Skill

A SOC analyst co-pilot that turns raw alert telemetry into a structured triage verdict. Built for L1/L2 analysts working in high-volume SOCs where consistency, MITRE coverage, and SOAR-ready output matter.

## When to use

Trigger this skill on any of the following:

- User pastes raw alert JSON, CSV, or log entries from Defender for Endpoint, Sentinel, Splunk ES, CrowdStrike Falcon, or similar platforms
- User asks "is this malicious?", "should I escalate?", "what is this alert doing?"
- User mentions XSOAR/Cortex/Shuffle playbook input
- User shares an IOC (IP, hash, domain, filename) and asks for assessment
- User describes observed behavior and wants MITRE mapping

## Triage workflow

Follow this exact sequence. Do not skip steps — consistency is the whole point.

### Step 1: Parse and normalize

Extract the following fields into a normalized structure. If a field is missing, mark it `null` rather than guessing:

- `alert_name` — the rule or detection that fired
- `timestamp` — UTC ISO 8601 preferred
- `source_platform` — Defender, Sentinel, Splunk, etc.
- `entities` — users, hosts, processes, IPs, hashes, files, URLs, registry keys
- `raw_evidence` — command lines, parent/child process chains, network connections
- `initial_severity` — what the tool assigned

### Step 2: MITRE ATT&CK mapping

Map the observed behavior to ATT&CK. Use the current MITRE ATT&CK Enterprise matrix. Output at least:

- **Tactic(s)** — e.g., TA0002 Execution, TA0005 Defense Evasion
- **Technique(s)** — e.g., T1059.001 PowerShell, T1055 Process Injection
- **Sub-technique** — if applicable

If the behavior matches multiple techniques, list all that apply in order of confidence. If mapping is uncertain, say so explicitly with a confidence note.

### Step 3: Severity reassessment

Reassess severity using these factors, not just the tool's label:

| Factor | Weight |
|--------|--------|
| Asset criticality (DC, crown jewel, prod server) | High |
| User privilege (standard, admin, service account) | High |
| Execution context (interactive, scheduled, remote) | Medium |
| IOC reputation (known-bad, unknown, known-good) | Medium |
| Kill-chain position (recon → impact) | High |
| Prevalence (first-seen vs common in env) | Medium |

Output one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.

### Step 4: Verdict and recommended action

Choose exactly one verdict:

- **TRUE POSITIVE — Confirmed malicious** → escalate to IR, contain host, preserve evidence
- **LIKELY TRUE POSITIVE — Suspicious, needs investigation** → open case, gather more context, interview user
- **BENIGN TRUE POSITIVE — Expected behavior** → document, tune rule, close
- **FALSE POSITIVE** → close with tuning recommendation
- **INSUFFICIENT DATA** → list specific queries/artifacts needed

### Step 5: Next actions

Provide a prioritized action list. Each action must be concrete and executable:

- Splunk/KQL queries to run (with actual syntax)
- Host isolation commands (Defender Live Response, CrowdStrike RTR)
- User notifications
- Ticket fields to update

## Output format

ALWAYS return this exact structure (Markdown + JSON block at the end):

```
# Alert Triage Report

**Alert:** <name>
**Time:** <UTC timestamp>
**Source:** <platform>

## Summary
<2-3 sentence plain-English explanation of what happened>

## MITRE ATT&CK
- Tactic: <ID + name>
- Technique: <ID + name>
- Confidence: <High|Medium|Low>

## Severity Assessment
- Tool-assigned: <original>
- Analyst-assessed: <reassessed>
- Rationale: <why it changed or stayed the same>

## Verdict
<one of the five verdicts above>

## Recommended Actions
1. <concrete action with query/command>
2. ...
3. ...

## Investigation Queries
```splunk
<ready-to-run SPL or KQL>
```

## SOAR Payload
```json
{
  "alert_id": "...",
  "verdict": "TRUE_POSITIVE",
  "severity": "HIGH",
  "mitre": {"tactic": "TA0002", "technique": "T1059.001"},
  "actions": ["isolate_host", "notify_user_manager"],
  "confidence": 0.85
}
```
```

## Script support

For batch triage of multiple alerts, use `scripts/batch_triage.py`:

```bash
python scripts/batch_triage.py alerts.json --output triage_report.md
```

The script accepts JSON arrays of alerts and produces a consolidated report. See the script for input format.

## Edge cases

- **Alert with only entity, no behavior**: do IOC enrichment reasoning (reputation, registration date, geolocation patterns) and flag as `INSUFFICIENT DATA` with enrichment queries.
- **Duplicate/correlated alerts**: note the correlation and treat as a single incident; elevate severity if the cluster suggests a kill-chain progression.
- **Known-benign patterns** (vulnerability scanners, admin tooling): verify against asset context before closing — attackers live off the land.
- **Missing context**: never invent details. List what you need in the Next Actions section.

## What NOT to do

- Do not produce verdicts without MITRE mapping
- Do not copy the tool-assigned severity without reassessment
- Do not recommend "monitor and watch" as a final action — that's a cop-out; always specify what to monitor for and for how long
- Do not hallucinate IOC reputation — if you don't know, say so and recommend VT/AbuseIPDB enrichment
