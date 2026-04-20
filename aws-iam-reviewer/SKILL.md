---
name: aws-iam-reviewer
description: Review AWS IAM configurations for least-privilege violations, ranked by blast radius. Takes the output of `aws iam get-account-authorization-details` or individual policy JSON and produces a prioritized findings report with remediation. Use this skill whenever the user shares AWS IAM policy JSON, mentions IAM review/audit, asks about AWS least privilege, wants to check for privilege escalation paths, is preparing for AWS Security Specialty certification, or needs to audit a customer's AWS account for an assessment. Also trigger for discussions of IAM Access Analyzer findings, SCP review, or cross-account trust policies.
---

# AWS IAM Reviewer

A cloud security audit assistant that analyzes AWS IAM configurations and surfaces least-privilege violations, privilege escalation paths, and risky trust relationships — each ranked by blast radius so remediation effort is spent on the highest-impact issues first.

## When to use

Trigger on any of:

- User shares IAM policy JSON (inline or attached)
- User pastes output of `aws iam get-account-authorization-details`
- User asks "is this policy too permissive?" or "review this IAM config"
- User mentions CloudTrail findings implicating IAM
- User is preparing for AWS Security Specialty and wants policy review practice
- User asks about IAM privilege escalation paths (e.g., iam:PassRole chains)
- Trust policy, role assumption, or cross-account access questions

## Input types supported

1. **Single policy** (managed or inline): raw JSON policy document
2. **Role definition**: role + attached policies + trust policy
3. **User/Group definition**: user + attached policies + group memberships
4. **Full account export**: output of `aws iam get-account-authorization-details`
5. **Access Analyzer findings**: JSON from `aws accessanalyzer list-findings`

Ask the user which type they're providing if it's ambiguous.

## Review workflow

### Step 1: Parse and categorize

Identify what you're looking at, then classify each statement in each policy by:

- **Effect**: Allow | Deny
- **Action scope**: specific action | service wildcard (`s3:*`) | full wildcard (`*`)
- **Resource scope**: specific ARN | wildcarded ARN | `*`
- **Condition**: any MFA, source IP, VPC, tag, or principal conditions

### Step 2: Identify findings

Check for these high-signal issues. Do not merely flag `*` — context matters. A logging role needing `s3:*` on its own log bucket is not a finding; an EC2 instance role with `s3:*` on `*` is.

#### Critical findings (privilege escalation paths)

| Finding | What to look for |
|---------|------------------|
| **iam:PassRole + compute launch** | `iam:PassRole` combined with `ec2:RunInstances`, `lambda:CreateFunction`, `glue:CreateJob`, `sagemaker:CreateTrainingJob` — allows launching compute under any role |
| **iam:CreatePolicyVersion** | Can overwrite existing policies to elevate privileges |
| **iam:AttachUser/RolePolicy** | Can attach AdministratorAccess to self |
| **iam:CreateAccessKey on other users** | Credential theft path |
| **sts:AssumeRole with permissive trust** | Trust policy allowing `Principal: "*"` without conditions |
| **iam:UpdateAssumeRolePolicy** | Can modify trust to allow self-assumption |
| **lambda:UpdateFunctionCode** + existing role | Can replace Lambda code to run as Lambda's role |

#### High findings (excessive blast radius)

- `Action: "*"` on `Resource: "*"` (full admin)
- Service-wide wildcards without resource scoping (`s3:*` on `*`)
- `NotAction` or `NotResource` statements (usually misunderstood, often overpermissive)
- Missing MFA condition on sensitive actions (delete, createAccessKey)
- Cross-account trust without external ID
- Resource-based policies granting access to `"*"` principal

#### Medium findings

- Overly broad resource wildcards (`arn:aws:s3:::*`)
- Inline policies (harder to audit than managed policies)
- Unused permissions (compare to CloudTrail last-accessed if available)
- Missing least-privilege on read vs write (why does a read service have write permissions?)
- Console access with no IP/MFA condition

#### Informational

- Policy version count at limit (5) — user can't add new versions
- Managed policy deviation from AWS-managed baseline
- Deprecated API actions still granted

### Step 3: Blast radius scoring

Score each finding 1–10 based on:

| Factor | Weight |
|--------|--------|
| Principal who has the permission | User (1-3) < Role (2-5) < Wildcard principal (7-10) |
| Action severity | Read (1-2) < Modify (4-6) < Delete/Admin (7-10) |
| Resource scope | Single ARN (1-2) < Wildcarded (5-7) < All resources (8-10) |
| Conditions present | MFA+IP reduces by 2; no conditions adds 1 |
| Cross-account exposure | Same account (0) < Trusted account (+2) < Public (+5) |

Final score = (Principal + Action + Resource + Conditions + CrossAccount) clamped to 1-10.

Sort findings by score descending in the report.

### Step 4: Generate remediation

For each finding, provide:

1. **Before** — the offending statement
2. **After** — a least-privilege replacement
3. **Verification** — AWS CLI command or Access Analyzer check to confirm the fix
4. **Tradeoffs** — any functionality the user might lose

## Output format

ALWAYS use this exact structure:

````
# AWS IAM Review Report

**Account/Scope:** <account ID or role/user reviewed>
**Review date:** <UTC timestamp>
**Policies analyzed:** <count>
**Findings:** <CRITICAL: N | HIGH: N | MEDIUM: N | INFO: N>

## Executive Summary
<3-5 sentences: top risks, overall posture, priority actions>

## Findings

### [CRITICAL] Score 9/10 — iam:PassRole chain enables EC2 privilege escalation
**Principal:** `arn:aws:iam::123456789012:role/DeveloperRole`
**Affected action(s):** `iam:PassRole`, `ec2:RunInstances`
**Blast radius:** Can launch EC2 under any role, including admin roles.

**Offending policy statement:**
```json
{
  "Effect": "Allow",
  "Action": ["iam:PassRole", "ec2:RunInstances"],
  "Resource": "*"
}
```

**Recommended fix:**
```json
{
  "Effect": "Allow",
  "Action": ["iam:PassRole"],
  "Resource": "arn:aws:iam::123456789012:role/AppWorkloadRole",
  "Condition": {
    "StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}
  }
},
{
  "Effect": "Allow",
  "Action": ["ec2:RunInstances"],
  "Resource": "*"
}
```

**Verification:**
```bash
aws accessanalyzer validate-policy --policy-document file://fixed.json --policy-type IDENTITY_POLICY
```

**Tradeoffs:** DeveloperRole can no longer pass arbitrary roles. If devs need to test multiple roles, whitelist them explicitly.

---

### [HIGH] Score 8/10 — ...
<continue for each finding>

## Unused Permissions
<only if CloudTrail last-accessed data is provided or requested>

## Positive Findings
<what's done well — always include; don't only critique>

## Methodology Note
This review analyzed static policy documents. It does not account for:
- Service Control Policies (SCPs) that may further restrict these permissions
- Permission boundaries
- Session policies
- Runtime CloudTrail-observed activity

Recommend running AWS IAM Access Analyzer and reviewing at least 90 days of CloudTrail for a complete picture.
````

## Script support

`scripts/parse_authorization_details.py` — handles the large JSON output of `aws iam get-account-authorization-details`, extracting each user/role/group and producing a per-principal summary for easier analysis.

`scripts/policy_lint.py` — a fast syntactic lint (checks for common mistakes like `NotAction` misuse, missing `Version`, invalid JSON) before the semantic review.

```bash
# Fetch your account's full IAM state
aws iam get-account-authorization-details > auth_details.json

# Parse into per-principal summaries
python scripts/parse_authorization_details.py auth_details.json \
    --output principals/

# Lint each policy
python scripts/policy_lint.py principals/role_DeveloperRole.json
```

The scripts produce structured data. The actual risk analysis, scoring, and remediation writing is done by Claude per the workflow above.

## Common privilege escalation patterns (reference)

These are the classic AWS privesc paths. Always check for these:

1. **CreateNewPolicyVersion** — `iam:CreatePolicyVersion` + `--set-as-default`
2. **SetExistingDefaultPolicyVersion** — `iam:SetDefaultPolicyVersion` to revert to a more permissive historical version
3. **CreateAccessKey** — on a privileged user you already have edit access to
4. **CreateLoginProfile** — on a user without console access to gain console access
5. **UpdateLoginProfile** — reset another user's console password
6. **AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy** — attach AdministratorAccess
7. **PutUserPolicy / PutGroupPolicy / PutRolePolicy** — inline policy injection
8. **AddUserToGroup** — add self to admin group
9. **UpdateAssumeRolePolicy** — modify trust to allow assumption
10. **PassRole chains** — `iam:PassRole` + a compute service (`ec2:*`, `lambda:*`, `glue:*`, `sagemaker:*`, `cloudformation:*`, `codebuild:*`, `ecs:*`, `datapipeline:*`)

Reference: Rhino Security Labs' AWS Privesc research and AWS's own "22 paths to privilege escalation" analysis.

## Edge cases and rules

- **Deny statements**: always evaluate explicit Deny first — an allow on `*` might still be effectively scoped by a Deny elsewhere. Note this in the analysis.
- **NotAction semantics**: `NotAction` with Allow is almost always wrong. It means "allow everything except these". Flag it as HIGH unless the user can justify.
- **Condition keys**: not all conditions are equal. `aws:SourceIp` without `aws:ViaAWSService: false` can be bypassed via AWS services. Note this nuance.
- **Resource wildcards in trust policies**: `Principal: "*"` without `Condition` is critical. With `aws:PrincipalOrgID` it may be acceptable.
- **Session policies vs identity policies**: a session policy further restricts — more restrictive is not a finding.

## What NOT to do

- Do not flag every `*` as a finding; evaluate in context
- Do not recommend removing permissions without explaining what functionality breaks
- Do not guess at the user's intent — ask if a role's purpose is unclear
- Do not trust the policy name (`ReadOnlyAccess`) as evidence of what it actually does; read the statements
