---
name: rag-eval-harness
description: Evaluate Retrieval-Augmented Generation (RAG) systems on retrieval quality (recall@k, precision), generation quality (faithfulness, answer relevance), and hallucination risk. Produces Databricks-compatible evaluation reports and Mosaic AI Agent Evaluation payloads. Use this skill whenever the user asks to evaluate a RAG pipeline, wants to know if a chatbot's answers are faithful to retrieved context, needs to benchmark vector search quality, mentions RAG metrics (recall@k, MRR, faithfulness, groundedness), or wants to build an eval dataset. Also trigger for Databricks GenAI evaluation, Mosaic AI Agent Framework testing, or LLM-as-judge setup for RAG.
---

# RAG Evaluation Harness

A structured evaluation framework for Retrieval-Augmented Generation systems. Turns a RAG test case (query + retrieved chunks + generated answer + optional ground truth) into a multi-metric evaluation with per-dimension scoring, failure analysis, and remediation recommendations. Designed to produce output compatible with Databricks Mosaic AI Agent Evaluation and MLflow.

## When to use

Trigger on any of:

- User asks to evaluate a RAG system, chatbot, or Q&A agent
- User shares retrieved chunks + an LLM answer and asks if it's "right" or "grounded"
- Questions about retrieval quality: recall@k, precision@k, MRR, NDCG
- Questions about generation quality: faithfulness, answer relevance, groundedness, context precision
- Mentions of Mosaic AI Agent Framework, MLflow evaluate, Databricks Vector Search
- Building or improving an LLM-as-judge rubric
- Hallucination detection or factual consistency checks

## Input types supported

1. **Single test case**: one query, retrieved chunks, generated answer, optional ground truth
2. **Test dataset (JSONL)**: multiple test cases for batch evaluation
3. **Live endpoint**: user shares an endpoint URL + test queries, skill coordinates retrieval + evaluation

If the user hasn't provided retrieved chunks, ask for them — you cannot evaluate retrieval blind.

## Evaluation dimensions

Score each dimension independently. Final output aggregates across all.

### Retrieval quality

| Metric | Measures | Required input |
|--------|----------|----------------|
| **Context Precision** | % of retrieved chunks that are relevant to the query | chunks + query |
| **Context Recall** | % of information in ground truth that appears in retrieved chunks | chunks + ground truth |
| **Recall@k** | Whether any of top-k chunks contains the answer | chunks + ground truth |
| **MRR** (Mean Reciprocal Rank) | Rank position of first relevant chunk | ranked chunks + relevance labels |
| **Chunk Coverage** | % of query's information needs addressed | query + chunks |

### Generation quality

| Metric | Measures | Required input |
|--------|----------|----------------|
| **Faithfulness** (Groundedness) | % of answer claims that are supported by retrieved context | chunks + answer |
| **Answer Relevance** | How well the answer addresses the query | query + answer |
| **Answer Correctness** | Factual agreement with ground truth | answer + ground truth |
| **Context Utilization** | Does the answer use the retrieved context, or ignore it? | chunks + answer |

### Safety & hallucination

| Metric | Measures |
|--------|----------|
| **Hallucination Score** | Claims in answer NOT supported by context or ground truth |
| **Refusal Appropriateness** | Did the model refuse when it should have (no relevant context)? |
| **PII Leakage** | Did the answer surface PII not in the original query? |
| **Prompt Injection Susceptibility** | Did retrieved content successfully manipulate the answer? |

## Evaluation workflow

### Step 1: Parse the test case

Extract and validate:

```
{
  "query": str,
  "retrieved_chunks": [{"id": str, "text": str, "score": float, "metadata": {...}}],
  "answer": str,
  "ground_truth": str | null,
  "ground_truth_chunks": [str] | null,
  "metadata": {"system": str, "k": int, ...}
}
```

If any required field is missing, list what's needed and stop.

### Step 2: Decompose the answer

Break the generated answer into individual claims (atomic assertions). Each claim gets independently graded for faithfulness and correctness.

Example:
- Answer: "The 2024 Q3 revenue was $12.3M, up 15% YoY, driven by enterprise sales."
- Claims:
  1. "2024 Q3 revenue was $12.3M"
  2. "Revenue was up 15% YoY"
  3. "Growth was driven by enterprise sales"

### Step 3: Score each dimension

For each claim, check: (a) is it in the retrieved chunks? (b) does it match ground truth? Score 0.0–1.0. Aggregate to dimension scores.

Use LLM-as-judge reasoning for subjective dimensions (answer relevance, context utilization). Use pattern matching for extractable facts (dates, numbers, entity names).

### Step 4: Classify failures

Every failure falls into one of these buckets. Use the taxonomy to drive remediation:

| Failure Mode | Symptom | Likely root cause |
|--------------|---------|-------------------|
| **Retrieval miss** | Relevant chunks NOT retrieved | Embedding model, chunk size, k too small |
| **Retrieval noise** | Irrelevant chunks retrieved | k too large, no reranking, weak embedding |
| **Hallucination** | Answer contains claims not in chunks | Model temperature, weak instruction, no grounding prompt |
| **Under-use** | Answer doesn't use retrieved context | Prompt doesn't require grounding |
| **Over-confidence** | Refuses to cite uncertainty | Missing "I don't know" affordance in prompt |
| **Context overflow** | Answer truncated or loses early context | Context window too small for k chunks |
| **Instruction leakage** | Answer reveals system prompt | Prompt design flaw |

### Step 5: Generate recommendations

Every finding must include a concrete remediation. Examples:

- "Increase k from 3 to 5" (retrieval miss)
- "Add a reranker (e.g., Cohere Rerank)" (retrieval noise)
- "Add grounding instruction: 'Only use information from the provided context'" (hallucination)
- "Add 'I don't know' fallback to system prompt" (over-confidence)

## Output format

ALWAYS use this structure:

````
# RAG Evaluation Report

**System:** <name or endpoint>
**Test date:** <UTC>
**Cases evaluated:** <N>
**Overall score:** <weighted avg 0.0-1.0>

## Dimension Scores

| Dimension | Score | Notes |
|-----------|-------|-------|
| Context Precision | 0.83 | 5 of 6 retrieved chunks relevant |
| Context Recall | 0.67 | Missing: Q2 product data |
| Faithfulness | 0.50 | 2 unsupported claims in answers |
| Answer Relevance | 0.92 | Directly addresses queries |
| Hallucination Risk | MEDIUM | 1 fabricated figure in case 3 |

## Per-Case Results

### Case 1: "What was Q3 revenue?"
- **Retrieval:** ✓ (4/5 chunks relevant)
- **Faithfulness:** ✗ (answer claims "driven by enterprise" — not in chunks)
- **Correctness:** partial (figure correct, attribution hallucinated)
- **Verdict:** REGRESSION — safe to ship but needs attribution guardrail

...

## Failure Mode Analysis

| Mode | Count | Priority |
|------|-------|----------|
| Hallucination | 3 | HIGH |
| Retrieval noise | 2 | MEDIUM |
| Under-use | 1 | LOW |

## Recommendations (ranked)

1. **[HIGH]** Add grounding instruction to system prompt. Example:
   ```
   "Answer only from the provided context. If the answer is not in the context,
   respond with 'I don't have enough information to answer that.'"
   ```

2. **[HIGH]** Enable source attribution. Require each claim to cite chunk IDs.

3. **[MEDIUM]** Add a reranker. Observed retrieval noise (1-2 irrelevant chunks per query).

4. **[LOW]** Increase chunk overlap from 50 to 100 tokens. Some answers miss cross-chunk context.

## Databricks / MLflow Export

```python
import mlflow
mlflow.log_metrics({
  "rag/context_precision": 0.83,
  "rag/context_recall": 0.67,
  "rag/faithfulness": 0.50,
  "rag/answer_relevance": 0.92,
  "rag/hallucination_rate": 0.20,
})
```

## Mosaic AI Agent Evaluation Payload

```json
{
  "request": "What was Q3 revenue?",
  "response": "...",
  "retrieved_context": [{"content": "...", "doc_uri": "..."}],
  "expected_response": "...",
  "guidelines": ["Answer must cite retrieved context"]
}
```
````

## Script support

`scripts/eval_dataset.py` batch-processes a JSONL eval file and produces aggregate metrics:

```bash
python scripts/eval_dataset.py --input eval_set.jsonl --output results.json
```

`scripts/decompose_claims.py` uses an LLM to break an answer into atomic claims — useful when evaluating long-form generations.

```bash
python scripts/decompose_claims.py --answer "..." --chunks chunks.json
```

Both scripts produce structured JSON that Claude then reasons over. Scripts do not perform the final judgment — Claude does, using the rubric above.

## Common pitfalls

- **No ground truth** — you can still evaluate retrieval precision and faithfulness, but NOT recall or correctness. Say so explicitly.
- **Short-answer bias** — "yes/no" answers inflate faithfulness scores. Always decompose into claims even when the answer is one sentence.
- **LLM-as-judge drift** — use a different model for judging than generation. Log judge model name in every eval.
- **Embedding-only relevance** — cosine similarity ≠ semantic relevance. Always sanity-check high-similarity chunks manually on first eval.
- **Evaluating 1 query** — single-case results are noise. Require at least 20 diverse cases before drawing conclusions. Call this out if the user has fewer.

## What NOT to do

- Do not evaluate retrieval quality without chunk text (scores alone mean nothing)
- Do not mark an answer correct just because it "sounds right" — check against ground truth or chunks
- Do not apply a single aggregate score without breaking down by dimension (hides failure modes)
- Do not recommend "improve the prompt" without specifying what to add or remove
