#!/usr/bin/env python3
"""
Fast syntactic linter for AWS IAM policy documents.

Checks for:
- Valid JSON
- Required fields (Version, Statement)
- Per-statement structure (Effect, Action/NotAction, Resource/NotResource)
- Common smells: wildcard actions, wildcard resources, NotAction+Allow,
  missing conditions on sensitive actions

This is a syntactic/structural check. It does NOT replace the deeper
semantic review Claude performs using the skill instructions.

Usage:
    python policy_lint.py policy.json
    python policy_lint.py policy.json --json
"""

import argparse
import json
import sys
from pathlib import Path


SENSITIVE_ACTIONS = {
    "iam:*",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "kms:Decrypt",
    "kms:*",
    "secretsmanager:GetSecretValue",
    "s3:DeleteBucket",
    "s3:*",
    "ec2:TerminateInstances",
    "rds:DeleteDBInstance",
    "lambda:UpdateFunctionCode",
    "*",
}


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def lint_statement(stmt: dict, idx: int) -> list[dict]:
    findings: list[dict] = []

    if not isinstance(stmt, dict):
        findings.append(
            {"severity": "ERROR", "stmt_idx": idx, "msg": "Statement is not an object"}
        )
        return findings

    effect = stmt.get("Effect")
    if effect not in {"Allow", "Deny"}:
        findings.append(
            {
                "severity": "ERROR",
                "stmt_idx": idx,
                "msg": f"Invalid or missing Effect: {effect}",
            }
        )

    has_action = "Action" in stmt
    has_not_action = "NotAction" in stmt
    has_resource = "Resource" in stmt
    has_not_resource = "NotResource" in stmt

    if has_action and has_not_action:
        findings.append(
            {
                "severity": "ERROR",
                "stmt_idx": idx,
                "msg": "Statement has both Action and NotAction",
            }
        )
    if not has_action and not has_not_action:
        findings.append(
            {
                "severity": "ERROR",
                "stmt_idx": idx,
                "msg": "Statement missing Action/NotAction",
            }
        )

    if has_resource and has_not_resource:
        findings.append(
            {
                "severity": "ERROR",
                "stmt_idx": idx,
                "msg": "Statement has both Resource and NotResource",
            }
        )

    # NotAction with Allow is nearly always wrong
    if has_not_action and effect == "Allow":
        findings.append(
            {
                "severity": "HIGH",
                "stmt_idx": idx,
                "msg": "NotAction with Effect:Allow — this grants everything EXCEPT the listed actions. "
                "This is almost always wider than intended.",
            }
        )

    actions = as_list(stmt.get("Action")) + as_list(stmt.get("NotAction"))
    resources = as_list(stmt.get("Resource")) + as_list(stmt.get("NotResource"))
    condition = stmt.get("Condition")

    # Full wildcard action
    if effect == "Allow" and "*" in actions:
        findings.append(
            {
                "severity": "HIGH",
                "stmt_idx": idx,
                "msg": "Action: '*' with Effect:Allow — grants all actions.",
            }
        )

    # Wildcard resource on sensitive action
    if effect == "Allow" and "*" in resources:
        sensitive_present = [
            a for a in actions if a in SENSITIVE_ACTIONS or a.endswith(":*")
        ]
        if sensitive_present:
            findings.append(
                {
                    "severity": "HIGH",
                    "stmt_idx": idx,
                    "msg": (
                        f"Resource: '*' with sensitive action(s): {sensitive_present}. "
                        "Scope the Resource or add Conditions."
                    ),
                }
            )

    # Sensitive actions without conditions
    if effect == "Allow" and not condition:
        for a in actions:
            if a in {"iam:PassRole", "iam:CreateAccessKey", "sts:AssumeRole"}:
                findings.append(
                    {
                        "severity": "MEDIUM",
                        "stmt_idx": idx,
                        "msg": (
                            f"{a} granted without any Condition — consider adding "
                            "iam:PassedToService, MFA, or SourceIP conditions."
                        ),
                    }
                )

    return findings


def lint_policy(doc: dict) -> list[dict]:
    findings: list[dict] = []

    if not isinstance(doc, dict):
        return [{"severity": "ERROR", "stmt_idx": None, "msg": "Policy is not an object"}]

    if "Version" not in doc:
        findings.append(
            {
                "severity": "MEDIUM",
                "stmt_idx": None,
                "msg": "Missing 'Version' — defaults to older 2008-10-17. Add '2012-10-17'.",
            }
        )
    elif doc["Version"] != "2012-10-17":
        findings.append(
            {
                "severity": "MEDIUM",
                "stmt_idx": None,
                "msg": f"Version is {doc['Version']}. Use '2012-10-17' unless you know why.",
            }
        )

    statements = doc.get("Statement")
    if statements is None:
        findings.append(
            {"severity": "ERROR", "stmt_idx": None, "msg": "Missing 'Statement'"}
        )
        return findings

    if isinstance(statements, dict):
        statements = [statements]

    for i, stmt in enumerate(statements):
        findings.extend(lint_statement(stmt, i))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="AWS IAM policy linter.")
    parser.add_argument("policy", type=Path, help="Policy JSON file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    try:
        with args.policy.open("r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {args.policy}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Invalid JSON: {e}")

    findings = lint_policy(doc)

    if args.json:
        print(json.dumps({"findings": findings}, indent=2))
        return 2 if any(f["severity"] == "ERROR" for f in findings) else 0

    if not findings:
        print("[OK] No lint findings.")
        return 0

    severity_order = {"ERROR": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    print(f"[+] {len(findings)} finding(s):\n")
    for f in findings:
        loc = f"stmt[{f['stmt_idx']}]" if f["stmt_idx"] is not None else "policy"
        print(f"  [{f['severity']:6s}] {loc}: {f['msg']}")

    return 2 if any(f["severity"] == "ERROR" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
