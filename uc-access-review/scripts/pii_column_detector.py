#!/usr/bin/env python3
"""
Heuristic PII column detector for Unity Catalog table descriptions.

Reads the output of `DESCRIBE TABLE EXTENDED` (JSON or CSV) and flags
columns whose names match known PII / sensitive patterns. Output is a
JSON list of flagged columns, useful to enrich UC access review input.

Usage:
    python pii_column_detector.py describe.json --output pii_flags.json
    python pii_column_detector.py describe.csv --csv --output pii_flags.json

Note: name-based detection is a heuristic. Always cross-check with real data
or a dedicated discovery tool (e.g., Databricks Lakehouse Monitoring, Macie).
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path


PII_PATTERNS: dict[str, list[str]] = {
    "email": [r"\bemail\b", r"mail_addr"],
    "phone": [r"\bphone\b", r"mobile", r"cell_num", r"tel\b"],
    "nric_fin": [r"\bnric\b", r"\bfin\b", r"ic_num", r"identity_num"],
    "passport": [r"passport"],
    "national_id": [r"\bssn\b", r"national_id", r"aadhaar", r"\btin\b"],
    "address": [r"\baddr\b", r"address", r"street", r"postal", r"zipcode"],
    "dob": [r"\bdob\b", r"birth", r"birthday"],
    "name": [r"first_name", r"last_name", r"full_name", r"given_name", r"surname"],
}

FINANCIAL_PATTERNS: dict[str, list[str]] = {
    "payment_card": [r"credit_card", r"card_num", r"ccn", r"pan\b"],
    "bank": [r"\biban\b", r"account_num", r"bank_acc", r"routing_num", r"swift"],
    "salary": [r"salary", r"compensation", r"income", r"payment_amt"],
}

HEALTH_PATTERNS: dict[str, list[str]] = {
    "medical_id": [r"patient_id", r"\bmrn\b", r"medical_record"],
    "diagnosis": [r"diagnosis", r"icd_code", r"medication"],
}

AUTH_PATTERNS: dict[str, list[str]] = {
    "secret": [r"password", r"passwd", r"secret", r"api_key", r"\btoken\b", r"private_key"],
}


ALL_PATTERNS: dict[str, dict[str, list[str]]] = {
    "pii": PII_PATTERNS,
    "financial": FINANCIAL_PATTERNS,
    "health": HEALTH_PATTERNS,
    "auth": AUTH_PATTERNS,
}


def classify_column(name: str) -> list[dict]:
    """Return list of {category, subtype, pattern} matches."""
    n = name.lower()
    matches: list[dict] = []
    for category, subtypes in ALL_PATTERNS.items():
        for subtype, patterns in subtypes.items():
            for pat in patterns:
                if re.search(pat, n):
                    matches.append(
                        {"category": category, "subtype": subtype, "pattern": pat}
                    )
                    break  # one hit per subtype is enough
    return matches


def load_columns(path: Path, is_csv: bool) -> list[dict]:
    """Return list of {name, type, table?} dicts."""
    cols: list[dict] = []
    if is_csv:
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("col_name") or row.get("column_name") or row.get("name")
                if name and not name.startswith("#"):
                    cols.append(
                        {
                            "name": name,
                            "type": row.get("data_type") or row.get("type"),
                            "table": row.get("table") or row.get("table_name"),
                        }
                    )
    else:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Accept either a flat list or {table, columns: [...]} structure
        if isinstance(data, dict) and "columns" in data:
            for c in data["columns"]:
                cols.append(
                    {
                        "name": c.get("name"),
                        "type": c.get("type"),
                        "table": data.get("table"),
                    }
                )
        elif isinstance(data, list):
            for c in data:
                if isinstance(c, dict):
                    cols.append(c)
                else:
                    cols.append({"name": str(c)})
    return cols


def main() -> int:
    parser = argparse.ArgumentParser(description="PII column detector for UC tables.")
    parser.add_argument("input", type=Path, help="DESCRIBE TABLE output (JSON or CSV)")
    parser.add_argument("--csv", action="store_true", help="Input is CSV format")
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output JSON")
    args = parser.parse_args()

    try:
        cols = load_columns(args.input, args.csv)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {args.input}")
    except (json.JSONDecodeError, KeyError) as e:
        sys.exit(f"[!] Parse error: {e}")

    if not cols:
        sys.exit("[!] No columns found in input.")

    flagged: list[dict] = []
    for col in cols:
        name = col.get("name", "")
        if not name:
            continue
        matches = classify_column(name)
        if matches:
            flagged.append(
                {
                    "column": name,
                    "type": col.get("type"),
                    "table": col.get("table"),
                    "classifications": matches,
                    "highest_category": matches[0]["category"],
                }
            )

    output = {
        "columns_scanned": len(cols),
        "flagged_count": len(flagged),
        "flagged": flagged,
    }
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"[+] Scanned {len(cols)} columns · flagged {len(flagged)}")
    if flagged:
        print("[+] Top flags:")
        for f in flagged[:10]:
            cats = ", ".join({c["subtype"] for c in f["classifications"]})
            print(f"    - {f['column']:30s}  [{cats}]")
    print(f"[+] Output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
