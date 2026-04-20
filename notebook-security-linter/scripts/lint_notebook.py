#!/usr/bin/env python3
"""
Databricks notebook security linter.

Scans a Databricks notebook (.py source, .ipynb, or .sql source format) for:
- Hardcoded secrets / credentials
- Unsafe shell execution patterns
- PII disclosure in display/print
- Cost anti-patterns
- Missing widget parameterization

Deterministic pattern-based checks. Claude handles judgment calls on
false-positive review (e.g., is that key in a docstring?).

Usage:
    python lint_notebook.py notebook.py
    python lint_notebook.py notebook.ipynb --json --output findings.json
    python lint_notebook.py notebook.py --severity HIGH

Exit code: 0 if clean, 1 if any HIGH, 2 if any CRITICAL.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path


# ============ Patterns ============

SECRET_PATTERNS = [
    # name, severity, regex, description
    ("aws_access_key", "CRITICAL", r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (
        "databricks_pat",
        "CRITICAL",
        r"dapi[0-9a-f]{32}",
        "Databricks personal access token",
    ),
    (
        "openai_key",
        "CRITICAL",
        r"sk-[A-Za-z0-9]{20,}",
        "OpenAI-style API key",
    ),
    (
        "anthropic_key",
        "CRITICAL",
        r"sk-ant-[A-Za-z0-9_-]{20,}",
        "Anthropic API key",
    ),
    (
        "slack_webhook",
        "HIGH",
        r"hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[A-Za-z0-9]+",
        "Slack incoming webhook",
    ),
    (
        "jwt_token",
        "HIGH",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "JWT token literal",
    ),
    (
        "password_assign",
        "HIGH",
        r"""(?i)password\s*=\s*["'][^"'$\s]{4,}["']""",
        "Hardcoded password assignment",
    ),
    (
        "api_key_assign",
        "HIGH",
        r"""(?i)(api[_-]?key|apikey)\s*=\s*["'][A-Za-z0-9+/=_-]{16,}["']""",
        "Hardcoded api_key assignment",
    ),
    (
        "jdbc_password",
        "HIGH",
        r"""(?i)jdbc:.*password=[^;&"'\s]+""",
        "JDBC connection string with inline password",
    ),
]

UNSAFE_SHELL = [
    (
        "sh_with_var",
        "HIGH",
        r"%sh[^\n]*\{[^}]+\}",
        "%sh cell with variable interpolation (injection risk)",
    ),
    (
        "os_system",
        "HIGH",
        r"os\.system\s*\(",
        "os.system call — prefer subprocess with arg list",
    ),
    (
        "shell_true",
        "HIGH",
        r"subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True",
        "subprocess shell=True — injection risk",
    ),
    (
        "pip_unversioned",
        "MEDIUM",
        r"(?m)^%pip install\s+(?!.*==)[A-Za-z0-9_\-]+(?!\S*==)",
        "%pip install without version pin",
    ),
]

PII_HINTS = [
    "email",
    "phone",
    "nric",
    "\\bfin\\b",
    "passport",
    "ssn",
    "address",
    "dob",
    "birth",
    "credit_card",
    "card_num",
    "password",
    "salary",
    "income",
]

PII_DISPLAY_PATTERNS = [
    (
        "display_pii",
        "HIGH",
        rf"""(?i)(display|\.show|print|\.toPandas)\s*\([^)]*({'|'.join(PII_HINTS)})""",
        "display/print on potentially PII-named column",
    ),
]

COST_PATTERNS = [
    (
        "collect_bare",
        "MEDIUM",
        r"\.collect\(\)",
        ".collect() — pulls entire DataFrame to driver",
    ),
    (
        "repartition_one",
        "MEDIUM",
        r"\.repartition\(\s*1\s*\)",
        "repartition(1) on write — serializes output",
    ),
    (
        "iterrows_spark",
        "LOW",
        r"\.iterrows\(\)",
        "iterrows() — pandas-style iteration, inefficient on Spark",
    ),
    (
        "select_star_first",
        "INFO",
        r"(?m)^\s*SELECT\s+\*",
        "SELECT * — consider explicit column list for clarity/cost",
    ),
]

WIDGET_ISSUES = [
    (
        "os_environ_prod",
        "MEDIUM",
        r"""os\.environ\[["'][^"']+["']\]""",
        "os.environ[...] — prefer dbutils.widgets or dbutils.secrets",
    ),
    (
        "sql_widget_interp",
        "HIGH",
        r"""spark\.sql\(f?["']?\s*SELECT[^"']*\{[^}]+\}""",
        "f-string SQL with widget interpolation — SQL injection risk",
    ),
]

ALL_CHECKS = [
    ("secrets", SECRET_PATTERNS),
    ("unsafe_shell", UNSAFE_SHELL),
    ("pii", PII_DISPLAY_PATTERNS),
    ("cost", COST_PATTERNS),
    ("widgets", WIDGET_ISSUES),
]


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ============ Notebook parsing ============


@dataclass
class Cell:
    index: int
    language: str
    source: str


@dataclass
class Finding:
    category: str
    rule: str
    severity: str
    cell_index: int
    line_in_cell: int
    match_redacted: str
    description: str


def redact(s: str, keep: int = 4) -> str:
    if len(s) <= 2 * keep + 3:
        return "*" * len(s)
    return f"{s[:keep]}...{s[-keep:]}"


def parse_py_source(text: str) -> list[Cell]:
    """Parse .py with Databricks cell markers."""
    cells: list[Cell] = []
    parts = re.split(r"(?m)^# COMMAND -+\s*$", text)
    for i, part in enumerate(parts):
        part = part.strip("\n")
        if not part.strip():
            continue
        language = "python"
        # Detect magic
        m = re.match(r"^# MAGIC %(\w+)", part)
        if m:
            language = m.group(1)
        cells.append(Cell(index=i, language=language, source=part))
    return cells


def parse_ipynb(text: str) -> list[Cell]:
    try:
        nb = json.loads(text)
    except json.JSONDecodeError:
        return []
    cells: list[Cell] = []
    default_lang = nb.get("metadata", {}).get("kernelspec", {}).get("language", "python")
    for i, cell in enumerate(nb.get("cells", [])):
        source = cell.get("source", "")
        if isinstance(source, list):
            source = "".join(source)
        lang = cell.get("cell_type", default_lang)
        if lang == "code":
            lang = default_lang
        cells.append(Cell(index=i, language=lang, source=source))
    return cells


def parse_sql_source(text: str) -> list[Cell]:
    cells: list[Cell] = []
    parts = re.split(r"(?m)^-- COMMAND -+\s*$", text)
    for i, part in enumerate(parts):
        part = part.strip("\n")
        if not part.strip():
            continue
        cells.append(Cell(index=i, language="sql", source=part))
    return cells


def load_notebook(path: Path) -> list[Cell]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".ipynb":
        return parse_ipynb(text)
    if path.suffix == ".sql":
        return parse_sql_source(text)
    # Default: python source
    return parse_py_source(text)


# ============ Scanning ============


def scan_cell(cell: Cell) -> list[Finding]:
    findings: list[Finding] = []
    lines = cell.source.splitlines()
    for category, checks in ALL_CHECKS:
        for rule, sev, pattern, description in checks:
            for i, line in enumerate(lines, start=1):
                for m in re.finditer(pattern, line):
                    matched = m.group(0)
                    findings.append(
                        Finding(
                            category=category,
                            rule=rule,
                            severity=sev,
                            cell_index=cell.index,
                            line_in_cell=i,
                            match_redacted=redact(matched),
                            description=description,
                        )
                    )
    return findings


def scan_notebook(cells: list[Cell]) -> list[Finding]:
    findings: list[Finding] = []
    for cell in cells:
        findings.extend(scan_cell(cell))
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 9),
            f.cell_index,
            f.line_in_cell,
        )
    )
    return findings


# ============ Output ============


def print_text_report(path: Path, cells: list[Cell], findings: list[Finding]) -> None:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("=" * 64)
    print(f"Notebook:       {path.name}")
    print(f"Cells scanned:  {len(cells)}")
    print(
        "Findings:       "
        f"CRITICAL: {counts['CRITICAL']}  "
        f"HIGH: {counts['HIGH']}  "
        f"MEDIUM: {counts['MEDIUM']}  "
        f"LOW: {counts['LOW']}  "
        f"INFO: {counts['INFO']}"
    )
    print("=" * 64)
    if not findings:
        print("[OK] No findings.")
        return

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            current_sev = f.severity
            print(f"\n--- {current_sev} ---")
        print(
            f"  [{f.category}/{f.rule}] cell {f.cell_index} line {f.line_in_cell}"
        )
        print(f"    {f.description}")
        print(f"    match: {f.match_redacted}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Databricks notebook security linter.")
    parser.add_argument("notebook", type=Path, help="Path to .py, .ipynb, or .sql file")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--output", type=Path, help="Write JSON to this path")
    parser.add_argument(
        "--severity",
        choices=list(SEVERITY_ORDER.keys()),
        default="INFO",
        help="Only report findings at this level or higher",
    )
    args = parser.parse_args()

    try:
        cells = load_notebook(args.notebook)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {args.notebook}")
    except Exception as e:
        sys.exit(f"[!] Failed to parse: {e}")

    if not cells:
        sys.exit("[!] Notebook contains no cells.")

    findings = scan_notebook(cells)
    floor = SEVERITY_ORDER[args.severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= floor]

    if args.json or args.output:
        payload = {
            "notebook": str(args.notebook),
            "cells_scanned": len(cells),
            "findings": [asdict(f) for f in findings],
        }
        text = json.dumps(payload, indent=2)
        if args.output:
            args.output.write_text(text, encoding="utf-8")
            print(f"[+] Wrote {len(findings)} findings -> {args.output}")
        else:
            print(text)
    else:
        print_text_report(args.notebook, cells, findings)

    if any(f.severity == "CRITICAL" for f in findings):
        return 2
    if any(f.severity == "HIGH" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
