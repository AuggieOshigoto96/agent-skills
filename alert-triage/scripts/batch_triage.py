#!/usr/bin/env python3
"""
Batch alert triage tool.

Reads a JSON file containing an array of alerts and produces a consolidated
triage report in Markdown. Designed to be called from XSOAR/SOAR playbooks
or run manually by SOC analysts.

Input format (alerts.json):
[
  {
    "alert_id": "defender-12345",
    "alert_name": "Suspicious PowerShell Execution",
    "timestamp": "2026-04-18T10:23:15Z",
    "source_platform": "MDE",
    "severity": "Medium",
    "entities": {
      "user": "jdoe",
      "host": "WKS-FIN-042",
      "process": "powershell.exe",
      "command_line": "powershell -enc <base64>",
      "parent_process": "winword.exe"
    },
    "raw_evidence": "..."
  }
]

Usage:
    python batch_triage.py alerts.json --output triage_report.md
    python batch_triage.py alerts.json --format json --output triage.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_alerts(path: Path) -> list[dict]:
    """Load and validate the alerts JSON file."""
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")
    except json.JSONDecodeError as e:
        sys.exit(f"[!] Invalid JSON in {path}: {e}")

    if not isinstance(data, list):
        sys.exit("[!] Expected a JSON array of alerts at the top level.")

    return data


def normalize_alert(alert: dict) -> dict:
    """Extract required fields, filling missing ones with null."""
    return {
        "alert_id": alert.get("alert_id") or alert.get("id"),
        "alert_name": alert.get("alert_name") or alert.get("title") or "Unnamed Alert",
        "timestamp": alert.get("timestamp") or alert.get("time"),
        "source_platform": alert.get("source_platform") or alert.get("source"),
        "initial_severity": alert.get("severity") or alert.get("initial_severity"),
        "entities": alert.get("entities") or {},
        "raw_evidence": alert.get("raw_evidence") or alert.get("raw"),
    }


def write_markdown_stub(alerts: list[dict], output: Path) -> None:
    """
    Write a Markdown scaffold that an analyst (or Claude) fills in.

    This script does NOT perform the LLM triage itself — it normalizes input
    and creates a reviewable structure. The triage logic lives in the skill
    instructions, so Claude applies its full reasoning per alert.
    """
    lines = []
    lines.append(f"# Batch Alert Triage Report")
    lines.append(f"")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"**Alert count:** {len(alerts)}")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    for i, alert in enumerate(alerts, start=1):
        n = normalize_alert(alert)
        lines.append(f"## Alert {i}: {n['alert_name']}")
        lines.append(f"")
        lines.append(f"- **ID:** `{n['alert_id']}`")
        lines.append(f"- **Time:** {n['timestamp']}")
        lines.append(f"- **Source:** {n['source_platform']}")
        lines.append(f"- **Tool severity:** {n['initial_severity']}")
        lines.append(f"")
        lines.append(f"### Entities")
        lines.append(f"```json")
        lines.append(json.dumps(n["entities"], indent=2))
        lines.append(f"```")
        lines.append(f"")
        lines.append(f"### Raw Evidence")
        lines.append(f"```")
        lines.append(str(n["raw_evidence"] or "(none provided)"))
        lines.append(f"```")
        lines.append(f"")
        lines.append(f"### Triage")
        lines.append(f"- [ ] MITRE mapped")
        lines.append(f"- [ ] Severity reassessed")
        lines.append(f"- [ ] Verdict reached")
        lines.append(f"- [ ] Actions recommended")
        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Wrote scaffold: {output} ({len(alerts)} alerts)")


def write_json_normalized(alerts: list[dict], output: Path) -> None:
    """Write normalized alerts as JSON for downstream SOAR ingestion."""
    normalized = [normalize_alert(a) for a in alerts]
    output.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
    print(f"[+] Wrote normalized JSON: {output} ({len(normalized)} alerts)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch alert triage normalizer.")
    parser.add_argument("input", type=Path, help="Path to alerts JSON file")
    parser.add_argument(
        "--output", "-o", type=Path, required=True, help="Output path"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    args = parser.parse_args()

    alerts = load_alerts(args.input)

    if args.format == "markdown":
        write_markdown_stub(alerts, args.output)
    else:
        write_json_normalized(alerts, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
