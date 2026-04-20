#!/usr/bin/env python3
"""
Sigma rule parser and validator.

Parses a Sigma YAML detection rule, validates its structure, and prints
a structured summary of the key fields. Does NOT perform conversion —
conversion logic lives in the skill instructions so Claude can reason
about field mapping.

Usage:
    python sigma_parse.py rule.yml
    python sigma_parse.py rule.yml --json        # machine-readable output
    python sigma_parse.py rule.yml --strict      # fail on warnings

Requires: pyyaml (pip install pyyaml)
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[!] Missing dependency: install pyyaml with `pip install pyyaml`")


REQUIRED_FIELDS = ["title", "logsource", "detection"]
RECOMMENDED_FIELDS = ["id", "status", "description", "level", "tags", "falsepositives"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


def load_sigma(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")
    except yaml.YAMLError as e:
        sys.exit(f"[!] YAML parse error in {path}: {e}")

    if not isinstance(rule, dict):
        sys.exit("[!] Top-level Sigma rule must be a YAML mapping.")

    return rule


def validate(rule: dict) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    # Required fields
    for f in REQUIRED_FIELDS:
        if f not in rule:
            errors.append(f"Missing required field: '{f}'")

    # Recommended fields
    for f in RECOMMENDED_FIELDS:
        if f not in rule:
            warnings.append(f"Missing recommended field: '{f}'")

    # Level validation
    if "level" in rule and rule["level"] not in VALID_LEVELS:
        warnings.append(
            f"Level '{rule['level']}' is non-standard. "
            f"Expected one of: {sorted(VALID_LEVELS)}"
        )

    # Status validation
    if "status" in rule and rule["status"] not in VALID_STATUS:
        warnings.append(
            f"Status '{rule['status']}' is non-standard. "
            f"Expected one of: {sorted(VALID_STATUS)}"
        )

    # Logsource validation
    logsource = rule.get("logsource", {})
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("product", "category", "service")):
            errors.append(
                "logsource must specify at least one of: product, category, service"
            )

    # Detection validation
    detection = rule.get("detection", {})
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("detection block is missing a 'condition' key")
        selections = [k for k in detection if k != "condition"]
        if not selections:
            errors.append("detection block has no selection blocks")

    # MITRE tag format
    tags = rule.get("tags", [])
    if isinstance(tags, list):
        bad_tags = [
            t
            for t in tags
            if t.startswith("attack.")
            and not (
                t.startswith("attack.t") or t.startswith("attack.ta") or "." in t[7:]
            )
        ]
        if bad_tags:
            warnings.append(
                f"MITRE tags look malformed: {bad_tags}. "
                "Expected format: 'attack.t1059.001' or 'attack.execution'"
            )

    return errors, warnings


def summarize(rule: dict) -> dict:
    """Build a structured summary of the rule."""
    detection = rule.get("detection", {})
    selection_keys = [k for k in detection if k != "condition"]

    return {
        "title": rule.get("title"),
        "id": rule.get("id"),
        "status": rule.get("status"),
        "level": rule.get("level"),
        "description": rule.get("description"),
        "logsource": rule.get("logsource"),
        "selection_blocks": selection_keys,
        "condition": detection.get("condition"),
        "mitre_tags": [t for t in rule.get("tags", []) if t.startswith("attack.")],
        "other_tags": [t for t in rule.get("tags", []) if not t.startswith("attack.")],
        "falsepositives": rule.get("falsepositives"),
        "references": rule.get("references"),
        "author": rule.get("author"),
        "date": rule.get("date"),
    }


def print_text_report(summary: dict, errors: list[str], warnings: list[str]) -> None:
    print("=" * 60)
    print(f" Sigma Rule Summary")
    print("=" * 60)
    print(f"Title:       {summary['title']}")
    print(f"ID:          {summary['id']}")
    print(f"Status:      {summary['status']}")
    print(f"Level:       {summary['level']}")
    print(f"Author:      {summary['author']}")
    print()
    print(f"Logsource:   {summary['logsource']}")
    print(f"Selections:  {summary['selection_blocks']}")
    print(f"Condition:   {summary['condition']}")
    print()
    if summary["mitre_tags"]:
        print(f"MITRE:       {', '.join(summary['mitre_tags'])}")
    if summary["falsepositives"]:
        print(f"FPs:         {summary['falsepositives']}")
    print()

    if errors:
        print("-" * 60)
        print(" ERRORS")
        print("-" * 60)
        for e in errors:
            print(f"  [X] {e}")
        print()

    if warnings:
        print("-" * 60)
        print(" WARNINGS")
        print("-" * 60)
        for w in warnings:
            print(f"  [!] {w}")
        print()

    if not errors and not warnings:
        print("[OK] Rule looks well-formed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sigma rule parser/validator.")
    parser.add_argument("rule", type=Path, help="Path to Sigma YAML rule")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--strict", action="store_true", help="Exit nonzero on warnings as well"
    )
    args = parser.parse_args()

    rule = load_sigma(args.rule)
    errors, warnings = validate(rule)
    summary = summarize(rule)

    if args.json:
        print(
            json.dumps(
                {"summary": summary, "errors": errors, "warnings": warnings},
                indent=2,
                default=str,
            )
        )
    else:
        print_text_report(summary, errors, warnings)

    if errors:
        return 2
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
