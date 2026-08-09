"""
Run a prompt-strategy experiment on the SOC triage benchmark dataset.

Combinations tested:
  - TRIAGE_PRECISE_PROMPT  → "pipeline_precise"
  - TRIAGE_CAUTIOUS_PROMPT → "pipeline_cautious"

Both run the full multi-agent pipeline (Supervisor → Triage → Investigation).
The only variable is the Triage Agent's classification strategy.

Uses langsmith.evaluate() so each run is properly registered as an experiment
and appears in the LangSmith UI under:
  Datasets & Experiments → soc-triage-benchmark → Experiments tab

Usage:
    python experiment.py
"""

import os
import re
from typing import Any
from dotenv import load_dotenv

load_dotenv()

if not os.getenv("OPENAI_API_KEY"):
    raise EnvironmentError("OPENAI_API_KEY is not set.")
if not os.getenv("LANGSMITH_API_KEY"):
    raise EnvironmentError(
        "LANGSMITH_API_KEY is not set — required for dataset access."
    )

from langsmith import evaluate as ls_evaluate
from langsmith.schemas import Run, Example

from agent import build_soc_graph, TRIAGE_PRECISE_PROMPT, TRIAGE_CAUTIOUS_PROMPT
from evaluator import create_soc_llm_judge, flag_for_human_review

DATASET_NAME = "soc-triage-benchmark"

EXPERIMENT_MATRIX = [
    (TRIAGE_PRECISE_PROMPT, "pipeline_precise"),
    (TRIAGE_CAUTIOUS_PROMPT, "pipeline_cautious"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def extract_decision(text: str) -> str:
    """Extract final_decision keyword from the Supervisor's verdict."""
    text_lower = text.lower()
    match = re.search(
        r"final_decision\s*[:\-]\s*(true_positive|false_positive|escalate)", text_lower
    )
    if match:
        return match.group(1)
    for keyword in ("true_positive", "false_positive", "escalate"):
        if keyword in text_lower:
            return keyword
    return "unknown"


# ---------------------------------------------------------------------------
# LangSmith evaluate() target + evaluator
# ---------------------------------------------------------------------------


def make_target(triage_prompt: str):
    """
    Returns a target function for langsmith.evaluate().

    The target receives each example's `inputs` dict and must return a dict.
    langsmith.evaluate() automatically links each run to the dataset example,
    which is what makes them appear in the Experiments tab.
    """
    graph = build_soc_graph(triage_prompt)

    def target(inputs: dict) -> dict:
        alert = {
            "alert_id": inputs.get("alert_id", "EVAL"),
            "rule": inputs.get("rule", ""),
            "source_ip": inputs.get("source_ip", ""),
            "destination_ip": inputs.get("destination_ip", "N/A"),
            "destination_port": inputs.get("destination_port", 0),
            "event_count": inputs.get("event_count", 0),
            "timestamp": inputs.get("timestamp", "N/A"),
            "severity": inputs.get("severity", "high"),
        }
        result = graph.invoke(
            {
                "alert": alert,
                "triage_result": None,
                "investigation_result": None,
                "final_verdict": None,
                "next_step": "",
            }
        )
        verdict = result.get("final_verdict", "")
        decision = extract_decision(verdict)
        print(f"  [{inputs.get('source_ip', '?')}] decision={decision}")
        return {"decision": decision, "full_response": verdict}

    return target


def decision_match_evaluator(run: Run, example: Example) -> dict:
    """
    Evaluator that scores 1 if the agent's decision matches the expected label,
    0 otherwise. LangSmith displays this score in the Experiments comparison view.
    """
    expected = (example.outputs or {}).get("decision", "")
    actual = (run.outputs or {}).get("decision", "unknown")
    return {
        "key": "decision_match",
        "score": 1 if actual == expected else 0,
        "comment": f"expected={expected}, got={actual}",
    }


def baseline_always_fp_evaluator(runs: list[Run], examples: list[Example]) -> dict:
    """
    Summary evaluator — runs once per experiment, not once per row.

    Reports what a rule with zero reasoning ("always guess false_positive")
    would score on this exact dataset. Real SOC alert streams run heavily
    false-positive-skewed, so this baseline is not automatically 0 — it can
    be high. An agent's decision_match score only means something once you
    know what doing nothing would have scored.
    """
    total = len(examples)
    fp_count = sum(
        1 for ex in examples if (ex.outputs or {}).get("decision") == "false_positive"
    )
    baseline = fp_count / total if total else 0.0
    return {
        "key": "baseline_always_fp",
        "score": baseline,
        "comment": (
            f"A rule that always guesses false_positive, with no reasoning at all, "
            f"would score {baseline:.0%} on this dataset ({fp_count}/{total} rows "
            f"are genuinely false_positive)."
        ),
    }


# ---------------------------------------------------------------------------
# Summary table (printed to terminal after all experiments complete)
# ---------------------------------------------------------------------------


def print_summary(all_results: dict[str, Any], baseline_pct: float) -> None:
    print("\n" + "=" * 70)
    print("EXPERIMENT RESULTS SUMMARY")
    print("=" * 70)
    print(
        f"BASELINE (always guess false_positive, zero reasoning): {baseline_pct:.1f}%"
    )
    print("-" * 70)
    print(
        f"{'Experiment':<25} {'ExactMatch':>11} {'LLM Judge':>10} {'NeedsReview':>13}"
    )
    print("-" * 70)

    for exp_name, results in all_results.items():
        rows = list(results)
        exact_scores, judge_scores = [], []

        for r in rows:
            for eval_result in r.get("evaluation_results", {}).get("results", []):
                if eval_result.score is None:
                    continue
                if getattr(eval_result, "key", "") == "decision_match":
                    exact_scores.append(eval_result.score)
                elif getattr(eval_result, "key", "") == "soc_judge_score":
                    judge_scores.append(eval_result.score)

        exact_acc = (
            sum(1 for s in exact_scores if s == 1) / len(exact_scores) * 100
            if exact_scores
            else 0
        )
        judge_avg = sum(judge_scores) / len(judge_scores) * 100 if judge_scores else 0
        needs_review = sum(1 for s in judge_scores if s < 0.75)

        print(
            f"{exp_name:<25} {exact_acc:>10.1f}% {judge_avg:>9.1f}% {needs_review:>11} run(s)"
        )

    print("=" * 70)
    print("\nView in LangSmith:")
    print("  Datasets & Experiments → soc-triage-benchmark → Experiments tab")
    print("  Annotation Queues → SOC-AGENT-annotation-queue  (human review)")
    print(
        "\n  TIP: In LangSmith Experiments, click + Compare to see exact_match vs"
        " soc_judge_score columns side by side."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    from langsmith import Client

    client = Client()
    examples = list(client.list_examples(dataset_name=DATASET_NAME))
    fp_count = sum(1 for ex in examples if (ex.outputs or {}).get("decision") == "false_positive")
    baseline_pct = (fp_count / len(examples) * 100) if examples else 0.0
    print(f"\nDataset '{DATASET_NAME}': {len(examples)} examples, {fp_count} labeled false_positive "
          f"({baseline_pct:.1f}% baseline).")

    all_results: dict[str, Any] = {}

    for triage_prompt, experiment_name in EXPERIMENT_MATRIX:
        print(f"\n{'─'*60}")
        print(f"Running experiment: {experiment_name}")
        print(f"{'─'*60}")

        results = ls_evaluate(
            make_target(triage_prompt),
            data=DATASET_NAME,
            evaluators=[
                decision_match_evaluator,  # exact match — kept for comparison
                create_soc_llm_judge(),  # LLM judge — semantic scoring 0.0–1.0
            ],
            summary_evaluators=[baseline_always_fp_evaluator],
            experiment_prefix=experiment_name,
            max_concurrency=1,
        )
        all_results[experiment_name] = results

        # Push runs below HUMAN_REVIEW_THRESHOLD to the annotation queue
        print(f"\nChecking for runs that need human review...")
        flag_for_human_review(results, experiment_name)
        print(f"Experiment '{experiment_name}' complete.")

    print_summary(all_results, baseline_pct)


if __name__ == "__main__":
    main()
