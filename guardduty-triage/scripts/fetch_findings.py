#!/usr/bin/env python3
"""
Fetch recent GuardDuty findings into a JSONL file for batch triage.

Wraps `aws guardduty list-findings` + `get-findings` via boto3.
Designed to be the input generator for Claude-based triage workflows.

Usage:
    python fetch_findings.py --region ap-southeast-1 --max 50 --output findings.jsonl
    python fetch_findings.py --region us-east-1 --severity HIGH --days 7 \\
        --output critical.jsonl

Requires: boto3, valid AWS credentials (env, profile, or IAM role)
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:
    sys.exit("[!] Install boto3: pip install boto3")


SEVERITY_FLOOR = {
    "LOW": 1.0,
    "MEDIUM": 4.0,
    "HIGH": 7.0,
}


def list_detectors(client) -> list[str]:
    """Return all detector IDs in the current region."""
    detectors: list[str] = []
    paginator = client.get_paginator("list_detectors")
    for page in paginator.paginate():
        detectors.extend(page.get("DetectorIds", []))
    return detectors


def list_finding_ids(
    client, detector_id: str, severity_floor: float, since_iso: str
) -> list[str]:
    """List finding IDs matching our filter (severity + freshness)."""
    criterion = {
        "severity": {"Gte": severity_floor},
        "updatedAt": {"Gte": int(datetime.fromisoformat(since_iso.replace("Z", "+00:00")).timestamp() * 1000)},
        "service.archived": {"Eq": ["false"]},
    }
    finding_ids: list[str] = []
    paginator = client.get_paginator("list_findings")
    for page in paginator.paginate(
        DetectorId=detector_id, FindingCriteria={"Criterion": criterion}
    ):
        finding_ids.extend(page.get("FindingIds", []))
    return finding_ids


def get_findings_batch(
    client, detector_id: str, finding_ids: list[str]
) -> list[dict]:
    """GuardDuty get-findings accepts up to 50 IDs per call."""
    out: list[dict] = []
    for i in range(0, len(finding_ids), 50):
        chunk = finding_ids[i : i + 50]
        resp = client.get_findings(DetectorId=detector_id, FindingIds=chunk)
        out.extend(resp.get("Findings", []))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch GuardDuty findings into JSONL for triage."
    )
    parser.add_argument("--region", type=str, required=True, help="AWS region")
    parser.add_argument(
        "--output", "-o", type=Path, required=True, help="Output JSONL path"
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Minimum severity floor (default LOW)",
    )
    parser.add_argument(
        "--days", type=int, default=7, help="Look back this many days (default 7)"
    )
    parser.add_argument(
        "--max", type=int, default=100, help="Cap total findings returned (default 100)"
    )
    parser.add_argument(
        "--profile", type=str, default=None, help="AWS named profile"
    )
    args = parser.parse_args()

    session_kwargs: dict = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    try:
        session = boto3.Session(**session_kwargs)
        client = session.client("guardduty")
    except NoCredentialsError:
        sys.exit("[!] No AWS credentials found. Set env vars or use --profile.")

    try:
        detectors = list_detectors(client)
    except (BotoCoreError, ClientError) as e:
        sys.exit(f"[!] Failed to list detectors: {e}")

    if not detectors:
        sys.exit(f"[!] No GuardDuty detectors in {args.region}. Is GD enabled?")

    since = datetime.now(timezone.utc) - timedelta(days=args.days)
    since_iso = since.isoformat()
    severity_floor = SEVERITY_FLOOR[args.severity]

    all_findings: list[dict] = []
    for det in detectors:
        try:
            ids = list_finding_ids(client, det, severity_floor, since_iso)
            if not ids:
                continue
            findings = get_findings_batch(client, det, ids[: args.max])
            all_findings.extend(findings)
            print(f"[+] Detector {det}: {len(findings)} findings")
        except (BotoCoreError, ClientError) as e:
            print(f"[!] Detector {det}: {e}", file=sys.stderr)

    all_findings = all_findings[: args.max]

    with args.output.open("w", encoding="utf-8") as f:
        for finding in all_findings:
            f.write(json.dumps(finding, default=str) + "\n")

    print(f"[+] Wrote {len(all_findings)} findings -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
