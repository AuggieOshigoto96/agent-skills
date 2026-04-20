---
name: uc-access-review
description: Review Databricks Unity Catalog grants for over-permissive access, wildcard privileges, missing masking policies on PII columns, stale principal bindings, and cross-catalog exposure risks. Use this skill whenever the user shares Unity Catalog grant JSON or `SHOW GRANTS` output, asks about Databricks data access, wants to audit UC permissions, needs to check who can read sensitive tables, or wants to translate a UC audit into a remediation plan. Also trigger for questions about row filters, column masks, dynamic views, or Databricks data governance.
---

# Unity Catalog Access Review

The data-plane equivalent of the AWS IAM Reviewer: takes Databricks Unity Catalog grant configurations and produces a findings report ranked by blast radius, with remediation SQL ready to paste.

## When to use

Trigger on any of:

- User shares JSON or CSV from `SHOW GRANTS` / `SHOW GRANTS ON CATALOG/SCHEMA/TABLE`
- User pastes output of `databricks unity-catalog permissions get`
- Questions about UC privileges: `SELECT`, `MODIFY`, `ALL PRIVILEGES`, `MANAGE`, `USE CATALOG`, `USE SCHEMA`
- User asks "who can read <table>?" or "is this permission structure safe?"
- Review of row filters, column masks, or dynamic views
- Audit prep for ISO 27001, SOC 2, PDPA involving data access controls

## Input types supported

1. **SHOW GRANTS output**: result of `SHOW GRANTS ON <securable>` (JSON or tabular)
2. **Securable graph export**: JSON describing catalog → schema → table hierarchy with grants at each level
3. **Permissions API response**: output of `databricks api get /api/2.1/unity-catalog/permissions/<type>/<name>`
4. **Effective permissions**: `SHOW GRANTS <principal> ON ...` to see transitive access

Ask the user which format if ambiguous.

## UC privilege model

Know this before reviewing. Unity Catalog grants are hierarchical and additive (no explicit deny):

| Object type | Key privileges |
|-------------|----------------|
| Metastore | CREATE CATALOG, MANAGE |
| Catalog | USE CATALOG, CREATE SCHEMA, MANAGE, ALL PRIVILEGES |
| Schema | USE SCHEMA, CREATE TABLE, CREATE FUNCTION, CREATE VOLUME, MANAGE |
| Table / View | SELECT, MODIFY, ALL PRIVILEGES |
| External location | READ FILES, WRITE FILES, CREATE EXTERNAL TABLE, CREATE EXTERNAL VOLUME, MANAGE |
| Storage credential | CREATE EXTERNAL LOCATION, MANAGE, READ FILES, WRITE FILES |
| Volume | READ VOLUME, WRITE VOLUME |
| Function | EXECUTE |

Principals can be users, service principals, or groups. Groups (especially `account users`, `users`) are the most common source of over-permissive access.

## Review workflow

### Step 1: Parse grants into a principal × securable × privilege matrix

Normalize everything into rows:

```json
{"principal": "group:analysts", "securable": "main.prod.customers", "privilege": "SELECT"}
```

If the input spans multiple levels (catalog + schema + table), resolve effective grants — a `SELECT` on the schema grants it on all tables in the schema.

### Step 2: Identify findings

Check for these, in order of blast radius:

#### Critical (score 8-10)

| Finding | What to look for |
|---------|------------------|
| **`ALL PRIVILEGES` on catalog** | Anyone granted catalog-level ALL PRIVILEGES can read+write+manage everything underneath |
| **`MANAGE` granted broadly** | MANAGE includes grant delegation — recipient can grant access to others |
| **Wildcard-like principal groups with write access** | `users`, `account users`, or org-wide groups with MODIFY on sensitive tables |
| **Service principal with `ALL PRIVILEGES`** | Automation running with full privileges — blast radius = everything automation can touch |
| **External location MANAGE granted widely** | Enables arbitrary external table creation pointing to unsafe S3/ADLS paths |

#### High (score 6-7)

- **No row filter on sensitive tables** (PII, financial records)
- **No column mask on PII columns** (email, phone, SSN/NRIC, FIN, payment)
- **Cross-workspace exposure** via shared metastore
- **Public group `account users` with SELECT on PII tables**
- **Stale service principals** (created >90 days ago, no recent usage — needs activity logs)
- **`MODIFY` granted to a read-focused group** (analyst groups should not MODIFY)

#### Medium (score 4-5)

- Schema-level grants that over-expose when new tables are added (tables inherit parent grants)
- Individual user grants instead of group grants (governance smell)
- Grants on deprecated tables (stale access to legacy PII)
- Missing `USE CATALOG` / `USE SCHEMA` chains (indicates partial visibility — may be intentional)

#### Informational

- Unused privileges (grantee hasn't accessed the object — requires activity logs)
- Function `EXECUTE` grants without corresponding schema access

### Step 3: Classify sensitive data

A finding is higher priority if the affected securable contains sensitive data. Use column-level hints:

- PII: `email`, `phone`, `nric`, `fin`, `passport`, `ssn`, `address`, `dob`, `birthday`
- Financial: `credit_card`, `iban`, `salary`, `payment`, `income`
- Health: `diagnosis`, `medication`, `patient_id`, `mrn`
- Auth: `password`, `password_hash`, `api_key`, `secret`, `token`

If column metadata isn't provided, ask for `DESCRIBE TABLE` output to assess sensitivity.

### Step 4: Blast radius scoring

Score each finding 1-10:

| Factor | Weight |
|--------|--------|
| Privilege severity (SELECT=3, MODIFY=6, ALL=8, MANAGE=9) | High |
| Principal breadth (individual=1, small group=3, org group=7, `users`=9) | High |
| Data sensitivity (internal=2, PII=7, financial/health=9) | High |
| Scope (single table=2, schema=5, catalog=8) | Medium |
| Masking presence (no mask on PII adds 2) | Medium |

### Step 5: Remediation SQL

Every finding must include ready-to-paste SQL:

- Revocation: `REVOKE <priv> ON <securable> FROM <principal>`
- Replacement with narrower grant: `GRANT SELECT ON main.prod.customers_masked TO `group:analysts``
- Column mask: `ALTER TABLE ... ALTER COLUMN email SET MASK mask_email USING COLUMNS ()`
- Row filter: `ALTER TABLE ... SET ROW FILTER filter_by_region ON (region)`

## Output format

ALWAYS return this structure:

````
# Unity Catalog Access Review

**Metastore:** <metastore id or name>
**Catalog reviewed:** <catalog name>
**Review date:** <UTC>
**Principals analyzed:** <count>
**Findings:** CRITICAL: N | HIGH: N | MEDIUM: N | INFO: N

## Executive Summary
<3-5 sentences: top risks, data exposure posture, priority actions>

## Findings

### [CRITICAL] Score 9/10 — `account users` granted SELECT on PII catalog
**Principal:** `group:account users`
**Securable:** `main.prod` (catalog)
**Privilege:** `SELECT` (inherited to all tables)
**Blast radius:** Every user in the workspace can read all PII tables in prod.

**Sensitive data exposed:**
- `main.prod.customers` — email, phone, nric
- `main.prod.transactions` — account_number, amount

**Current grant:**
```sql
GRANT SELECT ON CATALOG main.prod TO `account users`;
```

**Recommended fix:**
```sql
-- Revoke broad grant
REVOKE SELECT ON CATALOG main.prod FROM `account users`;

-- Grant narrowly to the appropriate analyst group
GRANT USE CATALOG ON CATALOG main.prod TO `group:prod_analysts`;
GRANT USE SCHEMA ON SCHEMA main.prod TO `group:prod_analysts`;
GRANT SELECT ON TABLE main.prod.customers_masked TO `group:prod_analysts`;

-- Add column masks on PII
CREATE FUNCTION mask_email (email STRING) RETURNS STRING
  RETURN CASE WHEN is_member('pii_approved') THEN email
              ELSE regexp_replace(email, '(?<=.).(?=.*@)', '*')
         END;

ALTER TABLE main.prod.customers
  ALTER COLUMN email SET MASK mask_email;
```

**Tradeoffs:** Non-analyst users lose read access to `main.prod`. Any dashboard or job running under a non-analyst identity will break. Coordinate migration.

---

### [HIGH] Score 7/10 — ...
<continue for each finding>

## Positive Findings
<what's done well — always include>

## Unused Permissions Review
<if activity logs provided: identify principals with grants but no access in N days>

## Methodology Note
This review analyzed static grant configurations. It does not account for:
- Row filters / column masks at runtime (unless `DESCRIBE` info provided)
- Workspace-level admin overrides
- Personal access tokens delegating user privileges to jobs
- Delta Sharing recipients (separate review needed)

Recommend enabling UC Audit Logs and reviewing 30-90 days of actual access patterns to identify unused grants.
````

## Script support

`scripts/parse_show_grants.py` — converts `SHOW GRANTS` output (CSV or JSON) into the normalized principal × securable × privilege matrix.

```bash
python scripts/parse_show_grants.py grants.json --output matrix.json
```

`scripts/pii_column_detector.py` — flags PII-likely columns based on name pattern matching. Used to enrich review input.

```bash
python scripts/pii_column_detector.py describe.json --output pii_flags.json
```

## Edge cases and rules

- **No deny semantics**: UC has no explicit DENY. The only way to restrict is to revoke. Say so when users ask "can I deny X?".
- **Inheritance**: grants on catalog apply to ALL schemas and tables within, including future ones. Flag catalog-level SELECT on any catalog containing PII as at least HIGH.
- **Workspace admins**: workspace admins bypass UC permissions on objects they own. Note this limitation if reviewing admin groups.
- **Delta Sharing**: shared tables can be accessed from outside the metastore. Detect presence of shares and flag as a separate review domain.
- **Legacy Hive metastore**: UC grants don't apply to `hive_metastore`. If grants reference it, note that legacy Table ACLs apply, which is a separate model.

## What NOT to do

- Do not flag every broad grant — some automation legitimately needs catalog-level access. Ask about intent first.
- Do not recommend revoking without naming exactly what will break.
- Do not treat groups like individuals — always resolve group membership size when possible before scoring blast radius.
- Do not assume column names perfectly indicate PII. A column named `user_id` could be a PII identifier OR an internal uuid. Ask if ambiguous.
