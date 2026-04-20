#!/usr/bin/env python3
"""
Run an adversarial corpus against a target LLM endpoint.

Supports:
- Anthropic Messages API
- OpenAI Chat Completions API
- Generic HTTP POST (configurable)

Captures request, response, latency, and token counts to a JSONL results file.
Rate-limits to 1 request/second by default.

Usage:
    # Anthropic
    export ANTHROPIC_API_KEY=...
    python run_tests.py --corpus corpus.jsonl --target anthropic \\
        --model claude-sonnet-4-5 --output results.jsonl

    # OpenAI
    export OPENAI_API_KEY=...
    python run_tests.py --corpus corpus.jsonl --target openai \\
        --model gpt-4o --output results.jsonl

    # Generic HTTP
    python run_tests.py --corpus corpus.jsonl --target generic \\
        --endpoint https://my-chatbot.example.com/api/chat \\
        --prompt-field "message" --output results.jsonl

Dependencies: requests (pip install requests)
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("[!] Install requests: pip install requests")


def call_anthropic(prompt: str, model: str, api_key: str) -> dict:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    r = requests.post(url, headers=headers, json=body, timeout=60)
    return {"status": r.status_code, "body": r.json() if r.ok else r.text}


def call_openai(prompt: str, model: str, api_key: str) -> dict:
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }
    r = requests.post(url, headers=headers, json=body, timeout=60)
    return {"status": r.status_code, "body": r.json() if r.ok else r.text}


def call_generic(prompt: str, endpoint: str, prompt_field: str, headers: dict) -> dict:
    body = {prompt_field: prompt}
    r = requests.post(endpoint, headers=headers, json=body, timeout=60)
    try:
        return {"status": r.status_code, "body": r.json()}
    except json.JSONDecodeError:
        return {"status": r.status_code, "body": r.text}


def extract_response_text(target: str, response: dict) -> str:
    """Best-effort extraction of the assistant message text."""
    body = response.get("body")
    if not isinstance(body, dict):
        return str(body)[:2000]

    if target == "anthropic":
        content = body.get("content", [])
        if isinstance(content, list):
            return "".join(
                block.get("text", "")
                for block in content
                if isinstance(block, dict) and block.get("type") == "text"
            )
    elif target == "openai":
        choices = body.get("choices", [])
        if choices and isinstance(choices[0], dict):
            return choices[0].get("message", {}).get("content", "")
    # Generic: return whole body as JSON string
    return json.dumps(body)[:2000]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run adversarial prompt corpus.")
    parser.add_argument("--corpus", type=Path, required=True, help="Corpus JSONL path")
    parser.add_argument(
        "--target",
        choices=["anthropic", "openai", "generic"],
        required=True,
        help="Target API type",
    )
    parser.add_argument("--model", type=str, help="Model name (for anthropic/openai)")
    parser.add_argument("--endpoint", type=str, help="URL (for generic)")
    parser.add_argument(
        "--prompt-field",
        type=str,
        default="message",
        help="JSON field name for prompt (generic only)",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra header as 'Key: value' (generic only, repeatable)",
    )
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output JSONL")
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="Seconds between requests (default 1.0)",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="Only run first N cases (for smoke tests)"
    )
    args = parser.parse_args()

    # Validate target-specific args
    if args.target == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            sys.exit("[!] Set ANTHROPIC_API_KEY environment variable.")
        if not args.model:
            sys.exit("[!] --model is required for anthropic target.")
    elif args.target == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            sys.exit("[!] Set OPENAI_API_KEY environment variable.")
        if not args.model:
            sys.exit("[!] --model is required for openai target.")
    else:  # generic
        if not args.endpoint:
            sys.exit("[!] --endpoint is required for generic target.")
        api_key = None

    # Parse extra headers for generic
    generic_headers = {"Content-Type": "application/json"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            generic_headers[k.strip()] = v.strip()

    # Load corpus
    cases: list[dict] = []
    with args.corpus.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))

    if args.limit:
        cases = cases[: args.limit]

    print(f"[+] Running {len(cases)} tests against {args.target}...")

    with args.output.open("w", encoding="utf-8") as out:
        for i, case in enumerate(cases, start=1):
            prompt = case["prompt"]
            start = time.time()
            try:
                if args.target == "anthropic":
                    response = call_anthropic(prompt, args.model, api_key)
                elif args.target == "openai":
                    response = call_openai(prompt, args.model, api_key)
                else:
                    response = call_generic(
                        prompt, args.endpoint, args.prompt_field, generic_headers
                    )
                error = None
            except Exception as e:
                response = {"status": None, "body": None}
                error = str(e)

            elapsed_ms = int((time.time() - start) * 1000)
            response_text = (
                extract_response_text(args.target, response) if not error else ""
            )

            record = {
                **case,
                "target": args.target,
                "model": args.model,
                "response_text": response_text,
                "response_raw": response,
                "latency_ms": elapsed_ms,
                "error": error,
            }
            out.write(json.dumps(record) + "\n")
            out.flush()

            status_icon = "X" if error else "OK"
            print(
                f"  [{i}/{len(cases)}] {status_icon} "
                f"[{case.get('owasp_category', '?')}] "
                f"latency={elapsed_ms}ms"
            )

            if i < len(cases):
                time.sleep(args.rate_limit)

    print(f"[+] Done. Results written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
