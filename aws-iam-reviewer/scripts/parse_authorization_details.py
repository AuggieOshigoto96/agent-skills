#!/usr/bin/env python3
"""
Parse output of `aws iam get-account-authorization-details` into per-principal
summaries for easier review.

Usage:
    aws iam get-account-authorization-details > auth.json
    python parse_authorization_details.py auth.json --output principals/

Produces one JSON file per principal (user, group, role) in the output
directory, each containing:
    - metadata (ARN, creation date, tags)
    - all attached managed policies (resolved to their statements)
    - all inline policies
    - trust policy (for roles)
    - instance profile (for roles)
    - group memberships (for users)
"""

import argparse
import json
import re
import sys
from pathlib import Path


def safe_filename(name: str) -> str:
    """Convert a principal name to a safe filename."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:200]


def build_policy_lookup(auth: dict) -> dict:
    """Return {policyArn: {name, default_version_document}}."""
    lookup: dict[str, dict] = {}
    for p in auth.get("Policies", []):
        arn = p.get("Arn")
        default_version_id = p.get("DefaultVersionId")
        default_doc = None
        for v in p.get("PolicyVersionList", []):
            if v.get("VersionId") == default_version_id:
                default_doc = v.get("Document")
                break
        lookup[arn] = {
            "name": p.get("PolicyName"),
            "default_version_id": default_version_id,
            "default_document": default_doc,
        }
    return lookup


def resolve_attached(
    attached: list[dict], policy_lookup: dict
) -> list[dict]:
    """Attach resolved policy documents to attached policy references."""
    resolved: list[dict] = []
    for a in attached:
        arn = a.get("PolicyArn")
        info = policy_lookup.get(arn, {})
        resolved.append(
            {
                "policy_arn": arn,
                "policy_name": a.get("PolicyName") or info.get("name"),
                "default_version_id": info.get("default_version_id"),
                "document": info.get("default_document"),
            }
        )
    return resolved


def process_user(user: dict, policy_lookup: dict) -> dict:
    return {
        "principal_type": "user",
        "name": user.get("UserName"),
        "arn": user.get("Arn"),
        "user_id": user.get("UserId"),
        "path": user.get("Path"),
        "create_date": user.get("CreateDate"),
        "tags": user.get("Tags", []),
        "group_list": user.get("GroupList", []),
        "attached_managed_policies": resolve_attached(
            user.get("AttachedManagedPolicies", []), policy_lookup
        ),
        "inline_policies": [
            {"name": p.get("PolicyName"), "document": p.get("PolicyDocument")}
            for p in user.get("UserPolicyList", [])
        ],
    }


def process_group(group: dict, policy_lookup: dict) -> dict:
    return {
        "principal_type": "group",
        "name": group.get("GroupName"),
        "arn": group.get("Arn"),
        "group_id": group.get("GroupId"),
        "create_date": group.get("CreateDate"),
        "attached_managed_policies": resolve_attached(
            group.get("AttachedManagedPolicies", []), policy_lookup
        ),
        "inline_policies": [
            {"name": p.get("PolicyName"), "document": p.get("PolicyDocument")}
            for p in group.get("GroupPolicyList", [])
        ],
    }


def process_role(role: dict, policy_lookup: dict) -> dict:
    return {
        "principal_type": "role",
        "name": role.get("RoleName"),
        "arn": role.get("Arn"),
        "role_id": role.get("RoleId"),
        "path": role.get("Path"),
        "create_date": role.get("CreateDate"),
        "trust_policy": role.get("AssumeRolePolicyDocument"),
        "max_session_duration": role.get("MaxSessionDuration"),
        "tags": role.get("Tags", []),
        "instance_profiles": [
            ip.get("InstanceProfileName")
            for ip in role.get("InstanceProfileList", [])
        ],
        "attached_managed_policies": resolve_attached(
            role.get("AttachedManagedPolicies", []), policy_lookup
        ),
        "inline_policies": [
            {"name": p.get("PolicyName"), "document": p.get("PolicyDocument")}
            for p in role.get("RolePolicyList", [])
        ],
        "permissions_boundary": role.get("PermissionsBoundary"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse aws iam get-account-authorization-details output."
    )
    parser.add_argument("input", type=Path, help="Path to auth details JSON")
    parser.add_argument(
        "--output", "-o", type=Path, required=True, help="Output directory"
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional path for an overall summary JSON",
    )
    args = parser.parse_args()

    try:
        with args.input.open("r", encoding="utf-8") as f:
            auth = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[!] Input not found: {args.input}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Invalid JSON: {e}")

    args.output.mkdir(parents=True, exist_ok=True)

    policy_lookup = build_policy_lookup(auth)

    counts = {"users": 0, "groups": 0, "roles": 0}

    # Users
    for user in auth.get("UserDetailList", []):
        record = process_user(user, policy_lookup)
        out = args.output / f"user_{safe_filename(record['name'])}.json"
        out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        counts["users"] += 1

    # Groups
    for group in auth.get("GroupDetailList", []):
        record = process_group(group, policy_lookup)
        out = args.output / f"group_{safe_filename(record['name'])}.json"
        out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        counts["groups"] += 1

    # Roles
    for role in auth.get("RoleDetailList", []):
        record = process_role(role, policy_lookup)
        out = args.output / f"role_{safe_filename(record['name'])}.json"
        out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        counts["roles"] += 1

    print(
        f"[+] Parsed {counts['users']} users, {counts['groups']} groups, "
        f"{counts['roles']} roles -> {args.output}"
    )

    if args.summary:
        summary = {
            "counts": counts,
            "managed_policies_total": len(policy_lookup),
            "principal_files": sorted(p.name for p in args.output.iterdir()),
        }
        args.summary.write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        print(f"[+] Summary: {args.summary}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
