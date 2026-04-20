#!/usr/bin/env python3
"""
Batch-evaluate a JSONL dataset of RAG test cases.

Each line must be a JSON object with:
  - query (str)
  - retrieved_chunks (list of {id, text, score})
  - answer (str)
  - ground_truth (str, optional)
  - ground_truth_chunks (list of str, optional)

Computes deterministic retrieval metrics (recall@k, precision@k, MRR)
and emits a scaffold for Claude to fill in judgment-based metrics
(faithfulness, answer relevance, hallucination).

Usage:
    python eval_dataset.py --input eval_set.jsonl --output results.json
    python eval_dataset.py --input eval_set.jsonl --output results.json --k 5
"""

import argparse
import json
import sys
from pathlib import Path
from statistics import mean


def load_cases(path: Path) -> list[dict]:
    cases: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as e:
                sys.exit(f"[!] Line {line_num}: invalid JSON — {e}")
    return cases


def validate_case(case: dict, idx: int) -> list[str]:
    missing = []
    for field in ("query", "retrieved_chunks", "answer"):
        if field not in case:
            missing.append(field)
    if missing:
        return [f"case {idx}: missing {missing}"]
    if not isinstance(case["retrieved_chunks"], list):
        return [f"case {idx}: retrieved_chunks must be a list"]
    return []


def retrieval_metrics(case: dict, k: int) -> dict:
    """Compute retrieval@k metrics where possible."""
    chunks = case.get("retrieved_chunks", [])[:k]
    gt_chunks = case.get("ground_truth_chunks") or []
    gt_chunk_ids = {c if isinstance(c, str) else c.get("id") for c in gt_chunks}

    metrics: dict = {
        "k": k,
        "chunks_retrieved": len(chunks),
    }

    if not gt_chunk_ids:
        metrics["note"] = "no ground_truth_chunks provided — precision/recall skipped"
        return metrics

    retrieved_ids = {c.get("id") for c in chunks if isinstance(c, dict)}
    hits = retrieved_ids & gt_chunk_ids

    precision_at_k = len(hits) / len(chunks) if chunks else 0.0
    recall_at_k = len(hits) / len(gt_chunk_ids) if gt_chunk_ids else 0.0

    # MRR: rank of first relevant chunk
    mrr = 0.0
    for rank, chunk in enumerate(chunks, start=1):
        if isinstance(chunk, dict) and chunk.get("id") in gt_chunk_ids:
            mrr = 1.0 / rank
            break

    metrics.update(
        {
            "precision_at_k": round(precision_at_k, 4),
            "recall_at_k": round(recall_at_k, 4),
            "mrr": round(mrr, 4),
            "hit": mrr > 0,
        }
    )
    return metrics


def judgment_scaffold() -> dict:
    """Placeholder for Claude-filled judgment metrics."""
    return {
        "faithfulness": None,
        "answer_relevance": None,
        "answer_correctness": None,
        "context_utilization": None,
        "hallucination_score": None,
        "failure_modes": [],
        "notes": "to be completed by Claude per the skill rubric",
    }


def aggregate(case_results: list[dict]) -> dict:
    """Aggregate deterministic metrics across cases."""
    prec = [r["retrieval"]["precision_at_k"] for r in case_results if "precision_at_k" in r["retrieval"]]
    rec = [r["retrieval"]["recall_at_k"] for r in case_results if "recall_at_k" in r["retrieval"]]
    mrr = [r["retrieval"]["mrr"] for r in case_results if "mrr" in r["retrieval"]]
    hits = [r["retrieval"].get("hit", False) for r in case_results]

    agg = {
        "cases": len(case_results),
        "retrieval": {},
    }
    if prec:
        agg["retrieval"]["precision_at_k_mean"] = round(mean(prec), 4)
    if rec:
        agg["retrieval"]["recall_at_k_mean"] = round(mean(rec), 4)
    if mrr:
        agg["retrieval"]["mrr_mean"] = round(mean(mrr), 4)
    if hits:
        agg["retrieval"]["hit_rate"] = round(sum(hits) / len(hits), 4)
    return agg


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch evaluate a RAG dataset.")
    parser.add_argument("--input", type=Path, required=True, help="Input JSONL")
    parser.add_argument("--output", type=Path, required=True, help="Output JSON")
    parser.add_argument("--k", type=int, default=5, help="Retrieval k (default 5)")
    args = parser.parse_args()

    cases = load_cases(args.input)
    if not cases:
        sys.exit("[!] No cases found in input")

    errors: list[str] = []
    for i, case in enumerate(cases):
        errors.extend(validate_case(case, i))
    if errors:
        for e in errors:
            print(f"[!] {e}", file=sys.stderr)
        sys.exit(2)

    case_results: list[dict] = []
    for i, case in enumerate(cases):
        case_results.append(
            {
                "case_id": case.get("id", f"case_{i}"),
                "query": case["query"],
                "retrieval": retrieval_metrics(case, args.k),
                "judgment": judgment_scaffold(),
            }
        )

    output = {
        "input": str(args.input),
        "k": args.k,
        "aggregate": aggregate(case_results),
        "cases": case_results,
    }

    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[+] Evaluated {len(cases)} cases at k={args.k}")
    print(f"[+] Deterministic metrics computed. Judgment metrics scaffolded.")
    print(f"[+] Output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
