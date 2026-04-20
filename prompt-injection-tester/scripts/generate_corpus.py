#!/usr/bin/env python3
"""
Generate an adversarial prompt corpus for LLM red-team testing.

Reads seed payloads from assets/payloads.json and produces a JSONL file
where each line is one test case. The corpus can then be fed to run_tests.py.

Usage:
    python generate_corpus.py --output corpus.jsonl
    python generate_corpus.py --output corpus.jsonl --categories LLM01,LLM06
    python generate_corpus.py --output corpus.jsonl --max-per-category 5
"""

import argparse
import json
import sys
import uuid
from pathlib import Path


DEFAULT_PAYLOADS_PATH = (
    Path(__file__).resolve().parent.parent / "assets" / "payloads.json"
)


def load_payloads(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"[!] Payload file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def flatten(
    payloads: dict, category_filter: set[str] | None, max_per_subcategory: int | None
) -> list[dict]:
    cases: list[dict] = []
    for category, subcategories in payloads.items():
        if category.startswith("_"):
            continue
        # Category matches if its OWASP ID prefix is in the filter
        cat_id = category.split("_")[0]  # e.g. "LLM01"
        if category_filter and not any(cat_id in f for f in category_filter):
            continue

        if not isinstance(subcategories, dict):
            continue

        for subcat, prompts in subcategories.items():
            for i, prompt in enumerate(prompts):
                if max_per_subcategory is not None and i >= max_per_subcategory:
                    break
                cases.append(
                    {
                        "test_id": str(uuid.uuid4()),
                        "owasp_category": category,
                        "subcategory": subcat,
                        "prompt": prompt,
                        "expected_behavior": "block_or_refuse",
                    }
                )
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate adversarial prompt corpus for red-team testing."
    )
    parser.add_argument(
        "--payloads",
        type=Path,
        default=DEFAULT_PAYLOADS_PATH,
        help="Path to payloads.json (default: ../assets/payloads.json)",
    )
    parser.add_argument(
        "--output", "-o", type=Path, required=True, help="Output JSONL path"
    )
    parser.add_argument(
        "--categories",
        type=str,
        default="",
        help="Comma-separated OWASP categories to include (e.g. LLM01,LLM06). Empty=all.",
    )
    parser.add_argument(
        "--max-per-category",
        type=int,
        default=None,
        help="Cap test cases per subcategory",
    )
    args = parser.parse_args()

    payloads = load_payloads(args.payloads)
    category_filter = (
        {c.strip() for c in args.categories.split(",") if c.strip()}
        if args.categories
        else None
    )

    cases = flatten(payloads, category_filter, args.max_per_category)

    with args.output.open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case) + "\n")

    print(f"[+] Generated {len(cases)} test cases -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
