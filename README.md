# Claude Cyber + Data Skills

An open-source toolkit of Claude Skills for security and data engineering work. Each skill is a self-contained folder (`SKILL.md` + scripts) that can be installed into Claude.ai, Claude Code, or the API individually.

Built for analysts and engineers who want consistent, structured, audit-ready output — not vibes.

🌐 **Live portfolio site:** https://AuggieOshigoto96.github.io/agent-skills/

---

## Cyber Security Track (5 skills · shipped)

### 1. `alert-triage/` — SIEM/EDR Alert Triage
Turns raw alert JSON (Defender, Splunk, Sentinel, CrowdStrike) into a structured triage verdict with MITRE ATT&CK mapping, reassessed severity, and SOAR-ready recommended actions. Includes a batch normalizer script for XSOAR/Cortex integration.

**Best for:** L1/L2 SOC analysts, shift leads standardizing triage quality across the team.

### 2. `sigma-converter/` — Sigma Rule Converter
Converts open-source Sigma YAML rules to Splunk SPL, Microsoft Sentinel KQL, Microsoft Defender XDR KQL, Elastic Lucene, or CrowdStrike queries. Preserves MITRE tagging, translates false-positive notes into tuning guidance, and flags field-mapping approximations. Ships with a standalone Sigma validator.

**Best for:** Detection engineers porting community rules into their own SIEM.

### 3. `prompt-injection-tester/` — LLM Red-Team Framework
Generates an OWASP LLM Top 10 adversarial corpus, runs it against Anthropic, OpenAI, or generic HTTP endpoints, and grades responses with heuristics plus an optional LLM-as-judge pass. Produces audit-ready assessment reports mapped to LLM01, LLM02, LLM06, and LLM07.

**Best for:** AI security engineers, AI governance analysts, and anyone auditing an LLM application before production.

### 4. `aws-iam-reviewer/` — AWS IAM Least-Privilege Audit
Reviews AWS IAM policies (single documents or full account exports) for least-privilege violations, ranked by blast radius. Identifies classic privilege escalation paths (iam:PassRole chains, policy version overwrite, trust policy abuse). Ships with an authorization-details parser and a syntactic policy linter.

**Best for:** Cloud security engineers, AWS Security Specialty candidates, and consultants running account audits.

### 5. `guardduty-triage/` — AWS GuardDuty Finding Triage
Cloud-native sibling to `alert-triage`. Takes raw GuardDuty findings and produces an incident verdict with MITRE ATT&CK for Cloud mapping, context-aware severity reassessment based on account/resource tier, and runnable remediation commands. Handles finding families across EC2, IAM, S3, EKS, Runtime Monitoring, and Malware Protection.

**Best for:** Cloud incident responders, SOC analysts supporting AWS-native workloads, AWS Security Specialty candidates.

---

## Data & ML Track (3 shipped · 5 on roadmap)

### 6. `rag-eval-harness/` — RAG Evaluation Harness
Evaluates Retrieval-Augmented Generation systems across retrieval quality (recall@k, precision, MRR), generation quality (faithfulness, answer relevance), and hallucination risk. Decomposes long-form answers into atomic claims and grades each. Outputs are compatible with Databricks Mosaic AI Agent Evaluation and MLflow.

**Best for:** GenAI engineers, AI quality teams, and anyone preparing for the Databricks GenAI Associate certification.

### 7. `uc-access-review/` — Unity Catalog Access Review
The data-plane equivalent of the AWS IAM Reviewer. Audits Databricks Unity Catalog grants for over-permissive access, wildcard privileges, missing masking policies on PII columns, and cross-workspace exposure. Produces findings ranked by blast radius with ready-to-paste remediation SQL (REVOKE + column mask + row filter).

**Best for:** Data governance teams, Databricks platform owners, analysts preparing for data access audits (PDPA, ISO 27001, SOC 2).

### 8. `notebook-security-linter/` — Databricks Notebook Security Linter
Scans Databricks notebooks (`.py`, `.ipynb`, `.sql`) for hardcoded secrets, PII disclosure in print/display, unsafe shell commands, and cost anti-patterns. Redacts secret values in the report (shows only first/last 4 chars), maps findings to `dbutils.secrets` remediation, and integrates into pre-commit hooks via a non-zero exit code on CRITICAL/HIGH findings.

**Best for:** Data engineers shipping notebooks to shared workspaces, security teams auditing data-plane code before migration.

---

## Quick start

Each skill is a standalone directory. Three ways to use them:

### Option A: Claude.ai (upload as Skills)

Requires Pro, Max, Team, or Enterprise plan.

1. Zip each skill folder individually (e.g., `alert-triage.zip`)
2. Claude.ai → Settings → Customize → Skills → `+` → Create skill → Upload
3. Toggle on, start chatting — Claude auto-triggers the relevant skill from your message

### Option B: Claude Code (filesystem)

```bash
# Drop skills into your Claude Code project
cp -r alert-triage guardduty-triage ~/your-project/.claude/skills/

cd ~/your-project
claude
> Triage every alert in alerts/ and write a report for each to reports/
```

### Option C: Paste as context (works everywhere)

In any Claude chat:

```
Use these instructions to triage this alert:

[paste contents of alert-triage/SKILL.md]

---

[paste your alert JSON]
```

## Example workflows

### Alert triage (cyber)

```bash
# Batch-normalize alerts for XSOAR ingestion:
python alert-triage/scripts/batch_triage.py alerts.json \
    --output triage_scaffold.md
```

### Sigma conversion (cyber)

```bash
# Validate Sigma YAML first
python sigma-converter/scripts/sigma_parse.py my_rule.yml

# Then ask Claude (with skill enabled):
#   "Convert this Sigma rule to Sentinel KQL targeting DeviceProcessEvents: ..."
```

### Prompt injection test (cyber)

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Generate corpus
python prompt-injection-tester/scripts/generate_corpus.py \
    --output corpus.jsonl

# Run against your target
python prompt-injection-tester/scripts/run_tests.py \
    --corpus corpus.jsonl \
    --target anthropic \
    --model claude-sonnet-4-5 \
    --output results.jsonl

# Grade with LLM-as-judge for ambiguous cases
python prompt-injection-tester/scripts/grade.py \
    --input results.jsonl \
    --output graded.jsonl \
    --judge
```

### AWS IAM review (cyber)

```bash
# Export your account state
aws iam get-account-authorization-details > auth.json

# Parse into per-principal files
python aws-iam-reviewer/scripts/parse_authorization_details.py auth.json \
    --output principals/

# Lint any policy
python aws-iam-reviewer/scripts/policy_lint.py principals/role_Dev.json

# Then have Claude (with the skill enabled) review each file
```

### GuardDuty triage (cyber)

```bash
# Pull recent findings from your account
python guardduty-triage/scripts/fetch_findings.py \
    --region ap-southeast-1 \
    --severity MEDIUM \
    --days 7 \
    --output findings.jsonl

# Then feed findings to Claude with the skill enabled for per-finding triage
```

### RAG evaluation (data)

```bash
# Prepare an eval dataset JSONL with query/chunks/answer/ground_truth
python rag-eval-harness/scripts/eval_dataset.py \
    --input eval_set.jsonl \
    --output results.json \
    --k 5
```

### Notebook linting (data)

```bash
# Pre-commit security check
python notebook-security-linter/scripts/lint_notebook.py \
    my_notebook.py --severity HIGH

# Exit code 2 on CRITICAL, 1 on HIGH — ready for CI hooks
```

### Unity Catalog audit (data)

```bash
# From a Databricks SQL warehouse or CLI:
#   SHOW GRANTS ON CATALOG main; > grants.json
#   DESCRIBE TABLE main.prod.customers; > describe.json

# Detect PII-likely columns
python uc-access-review/scripts/pii_column_detector.py describe.json \
    --output pii_flags.json

# Then have Claude review grants.json + pii_flags.json using the skill
```

## Python requirements

Tested on Python 3.10+. Individual script dependencies:

- `sigma-converter/` — `pyyaml`
- `prompt-injection-tester/run_tests.py` + `grade.py (--judge)` — `requests`
- `guardduty-triage/fetch_findings.py` — `boto3`

Other scripts are stdlib-only.

```bash
pip install pyyaml requests boto3
```

## Design principles

All eight skills follow the same conventions intentionally:

1. **Scripts handle deterministic work; Claude handles judgment.** Parsers, linters, and API callers are in Python. Reasoning (MITRE mapping, blast-radius scoring, claim decomposition, remediation synthesis) lives in SKILL.md for Claude to apply.
2. **Structured, reproducible output.** Every skill prescribes an exact output format so downstream consumers — SOAR playbooks, audit reports, MLflow, ticket systems — can parse results reliably.
3. **Remediation always included.** A triage without next-step commands isn't finished. A finding without fix SQL isn't actionable. Each skill produces concrete, runnable remediations.
4. **Fail loud, not silent.** Scripts exit non-zero on errors. Claude flags uncertainty instead of guessing. Secret values are redacted in reports.

## Portfolio site

The `docs/` folder serves a live GitHub Pages site with animated demos of each skill. To deploy: push to GitHub, enable Pages pointing to `/docs`. See `docs/README.md` for full setup.

## Authorized use

`prompt-injection-tester/` is for defensive security testing of systems you own or have written authorization to test. Do not use it against third-party production services without permission.

## License

MIT.
