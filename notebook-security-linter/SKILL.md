---
name: notebook-security-linter
description: Scan Databricks notebooks (.py, .ipynb, .dbc, .sql source format) for hardcoded secrets, raw credentials, unsafe shell commands, PII in print/display statements, missing Databricks Secrets usage, and cost anti-patterns. Use this skill whenever the user shares a Databricks notebook, asks to "review this notebook for security issues", mentions Databricks Secrets, wants to check if a notebook is safe to commit, or is preparing a notebook for code review. Also trigger for questions about `dbutils.secrets`, `%sh` hazards, widget parameterization, or cluster policies in notebooks.
---

# Databricks Notebook Security Linter

Scans Databricks notebooks for common security and quality issues before they hit a shared workspace or version control. Covers secrets, PII, unsafe shell execution, and cost patterns — all mapped to concrete remediations.

## When to use

Trigger on any of:

- User shares a Databricks notebook in any format (`.py`, `.ipynb`, `.sql`, exported `.dbc`)
- User asks "is this notebook safe to push?" or "review this for secrets"
- Mentions of `dbutils.secrets`, widget usage, Databricks workspace rules
- Pre-commit review of any notebook file
- Audit of a notebook batch (e.g., auditing all notebooks in a repo before migration)

## Input types supported

1. **Python source** (`.py` with Databricks cell markers `# COMMAND ----------`)
2. **Jupyter notebook** (`.ipynb` JSON)
3. **SQL notebook** (`.sql` with `-- COMMAND ----------`)
4. **Raw code snippet** pasted without format
5. **Multiple notebooks** in a zipped repo or list

If the format is ambiguous, the linter script auto-detects. If pasted raw, ask what language.

## Check categories

### 1. Secrets & credentials (CRITICAL)

| Check | Pattern |
|-------|---------|
| Hardcoded AWS access key | `AKIA[0-9A-Z]{16}` |
| Hardcoded AWS secret | 40-char base64 near key reference |
| Databricks PAT | `dapi[0-9a-f]{32}` |
| Generic API key assignment | `api_key\s*=\s*["'][A-Za-z0-9+/=_-]{16,}["']` |
| Connection strings with password | `password=<literal>` in JDBC/ODBC URL |
| `password = "..."` literal | direct assignment |
| Azure storage key | 88-char base64 with `==` |
| OpenAI/Anthropic key | `sk-...` / `sk-ant-...` |
| Hardcoded JWT | `eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}` |
| Slack webhook | `hooks.slack.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+` |

Replacement pattern:
```python
# Bad
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Good
AWS_KEY = dbutils.secrets.get(scope="prod-secrets", key="aws-access-key")
```

### 2. Unsafe shell execution (HIGH)

- `%sh` cells with no input sanitization
- `dbutils.fs.run` or `os.system` with variable interpolation
- `subprocess.Popen(shell=True, ...)` with user-supplied arguments
- `pip install` from arbitrary URLs (vs. pinned versions or internal registry)

Example finding:
```python
# HIGH — command injection risk
user_filter = dbutils.widgets.get("user_filter")
%sh grep {user_filter} /data/logs.txt
```

### 3. PII disclosure (HIGH)

- `print()` / `display()` on unmasked PII columns
- `df.show()` on tables known to contain PII
- `.toPandas().head()` without PII handling
- Notebook results persisted with PII visible

Heuristic: look for column references matching PII patterns (see `pii_column_detector` patterns), and for any display call on those frames.

### 4. Unsafe cluster configuration (MEDIUM)

- `%pip install` of packages without version pins
- `spark.conf.set` of credentials directly (should use secrets)
- `spark.sparkContext._jvm.org.apache.hadoop.conf.Configuration` hacks
- Accessing `/dbfs/` mount that has no ACL
- Use of deprecated `dbutils.fs.mount` with hardcoded keys

### 5. Widget and parameterization issues (MEDIUM)

- No widgets defined but notebook hardcodes environment (prod table name, etc.)
- Widget values used in SQL without escaping (SQL injection)
- Notebook uses `os.environ["..."]` instead of `dbutils.widgets.get(...)`
- Widget default values contain production identifiers

### 6. Cost anti-patterns (LOW-MEDIUM)

- `.collect()` on large DataFrames pulling everything to driver
- `.count()` before every join (triggers full scan)
- `repartition(1)` on large writes (forces single-threaded write)
- Pandas `for row in df.iterrows()` loops on Spark dataframes
- Multiple scans of the same dataframe without caching
- Very wide `SELECT *` in the first cell of an exploratory notebook

### 7. Governance & hygiene (INFO)

- Missing cell 1 header comment with owner, purpose, last updated
- No `%md` cells explaining logic
- TODO/FIXME comments left in (count and list)
- `import *` from ambiguous modules
- Dead cells that run `pass` or are commented out

## Review workflow

### Step 1: Parse the notebook

Detect format. Normalize into cells: each cell has `language` (python, sql, scala, r, sh, md) and `source` (text).

### Step 2: Run check categories

Run each category in parallel. For each hit, record:
- Category + rule name
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Cell number and line
- Match snippet (redacted if a secret)
- Recommended fix

### Step 3: Redact sensitive matches in the report

**CRITICAL**: if a finding contains an actual secret value, show only the first 4 and last 4 chars in the report. Example: `AKIA...MPLE` not the full key. The finding is about the location, not the leaked value.

### Step 4: Prioritize and group

Group findings by severity, then by category. Within each group, list by cell number.

## Output format

ALWAYS return this structure:

````
# Notebook Security Review

**Notebook:** <filename or title>
**Cells scanned:** <N>
**Findings:** CRITICAL: N | HIGH: N | MEDIUM: N | LOW: N | INFO: N

## Executive Summary
<2-4 sentences: worst issues, overall hygiene, commit-readiness verdict>

**Verdict:** <DO NOT COMMIT | COMMIT AFTER FIXES | SAFE TO COMMIT>

## Critical Findings

### [CRITICAL] Hardcoded AWS access key — Cell 3, line 12
**Rule:** `secrets/aws-access-key`
**Evidence (redacted):**
```python
AWS_KEY = "AKIA...MPLE"
```
**Recommended fix:**
```python
AWS_KEY = dbutils.secrets.get(scope="prod-secrets", key="aws-access-key")
```
**Action required:** This key must be rotated immediately if this notebook has ever been committed, shared, or exported. AWS access keys in public repos are indexed by attackers within minutes.

---

## High-Severity Findings

### [HIGH] PII displayed to notebook output — Cell 7
... (same structure)

## Medium / Low / Info
<grouped by severity, briefer format>

## Remediation Checklist

- [ ] Rotate AWS access key (treat as compromised)
- [ ] Move all 3 hardcoded credentials to `dbutils.secrets`
- [ ] Remove `display()` calls on PII columns in cells 5, 7, 14
- [ ] Pin `%pip install` packages to specific versions
- [ ] Add cell 1 header with owner + purpose

## Databricks Secrets Setup (if needed)

```bash
# Create a secret scope
databricks secrets create-scope --scope prod-secrets

# Add secrets
databricks secrets put-secret prod-secrets aws-access-key
databricks secrets put-secret prod-secrets aws-secret-key
```

Then in the notebook:
```python
aws_key = dbutils.secrets.get(scope="prod-secrets", key="aws-access-key")
aws_secret = dbutils.secrets.get(scope="prod-secrets", key="aws-secret-key")
```
````

## Script support

`scripts/lint_notebook.py` runs the full check suite on a notebook file and outputs findings as JSON or text:

```bash
python scripts/lint_notebook.py my_notebook.py
python scripts/lint_notebook.py my_notebook.ipynb --json --output findings.json
python scripts/lint_notebook.py my_notebook.sql --severity HIGH  # only HIGH+
```

Returns non-zero exit on CRITICAL or HIGH findings — suitable for pre-commit hooks and CI pipelines.

## Edge cases and rules

- **False positives on example code**: notebooks teaching Databricks secrets may contain sample key-like patterns inside docstrings. If a match is inside a markdown cell or a multi-line string clearly labeled "EXAMPLE" / "FAKE", downgrade severity and note.
- **Scala / R cells**: secret patterns apply across languages. Shell patterns (`%sh`) apply regardless of cell language.
- **External widgets**: if the notebook is orchestrated by a Databricks Workflow with secrets passed in as parameters, `dbutils.widgets.get("aws_key")` is acceptable and not a finding.
- **Legacy Hive metastore tables**: flagging PII on `hive_metastore.*` should still apply — governance is looser there, not absent.
- **Multi-language notebooks**: track cell language for each finding. Secret in a `%scala` cell looks different from a Python cell.

## What NOT to do

- Do not print actual secret values in the report (always redact to 4+4 chars)
- Do not recommend `os.environ` as a fix — use `dbutils.secrets` for proper secret scoping
- Do not mark a notebook "safe" just because it passes secret detection — check PII disclosure and unsafe shell too
- Do not suggest deleting cells without explaining what functionality they provide
