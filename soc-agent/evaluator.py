"""
SOC-specific LLM-as-judge evaluator with human-in-the-loop confirmation.

Why LLM judge instead of exact match:
  Exact match treats "escalate" != "true_positive" as WRONG, even though both
  are correct SOC actions for a confirmed threat. The LLM judge understands
  semantic equivalence in SOC context.

Human-in-the-loop pattern:
  - Runs scoring >= HUMAN_REVIEW_THRESHOLD are treated as auto-confirmed.
  - Runs scoring <  HUMAN_REVIEW_THRESHOLD are pushed to the LangSmith
    annotation queue so a human analyst makes the final call.

Usage (imported by experiment.py):
    from evaluator import create_soc_llm_judge, flag_for_human_review
"""

import re
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langsmith import Client
from langsmith.schemas import Run, Example

# Runs below this score go to the annotation queue for human confirmation.
HUMAN_REVIEW_THRESHOLD = 0.75

# Must match the queue you created in LangSmith UI.
ANNOTATION_QUEUE_NAME = "SOC-AGENT-annotation-queue"

# ---------------------------------------------------------------------------
# Judge prompt
# ---------------------------------------------------------------------------

_JUDGE_PROMPT = """\
You are a senior SOC analyst reviewing a junior analyst's triage decision.

ALERT CONTEXT
  Alert    : {alert}
  Rule     : {rule}
  Source IP: {source_ip}

TRIAGE RESULT
  Expected decision : {expected_decision}
  Agent's decision  : {actual_decision}
  Agent's reasoning : {agent_response}

SCORING RULES
  - "escalate" and "true_positive" are BOTH acceptable for a confirmed real threat.
    Do NOT penalise the agent for choosing one over the other when the threat is real.
  - "false_positive" is only correct if the alert is genuinely benign.
  - Completely wrong decision (e.g. false_positive for a real Tor exit node attack) = 0.
  - Correct decision but wrong severity = 0.5.
  - Correct decision AND correct severity = 1.0.

Respond in exactly this format (no extra text):
score: <0.0 to 1.0>
reasoning: <one concise sentence explaining the score>
"""


# ---------------------------------------------------------------------------
# Score parser
# ---------------------------------------------------------------------------

def _parse_judge_response(text: str) -> tuple[float, str]:
    score = 0.5  # safe default for unparseable responses
    reasoning = text.strip()

    score_match = re.search(r"score:\s*([\d.]+)", text, re.IGNORECASE)
    if score_match:
        score = max(0.0, min(1.0, float(score_match.group(1))))

    reasoning_match = re.search(r"reasoning:\s*(.+?)(?:\n|$)", text, re.IGNORECASE)
    if reasoning_match:
        reasoning = reasoning_match.group(1).strip()

    return score, reasoning


# ---------------------------------------------------------------------------
# Evaluator factory
# ---------------------------------------------------------------------------

def create_soc_llm_judge():
    """
    Returns a LangSmith-compatible evaluator function.

    Uses gpt-4o-mini as the judge (cheap, fast, sufficient for scoring).
    Scores 0.0–1.0 with reasoning stored as a comment in LangSmith.
    """
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    def evaluator(run: Run, example: Example) -> dict:
        expected      = (example.outputs or {}).get("decision", "")
        actual        = (run.outputs or {}).get("decision", "unknown")
        full_response = (run.outputs or {}).get("full_response", "")

        prompt = _JUDGE_PROMPT.format(
            alert=example.inputs.get("alert", "N/A"),
            rule=example.inputs.get("rule", "N/A"),
            source_ip=example.inputs.get("source_ip", "N/A"),
            expected_decision=expected,
            actual_decision=actual,
            agent_response=full_response[:600],
        )

        response = llm.invoke([HumanMessage(content=prompt)])
        score, reasoning = _parse_judge_response(response.content)

        review_flag = " ← NEEDS HUMAN REVIEW" if score < HUMAN_REVIEW_THRESHOLD else ""
        print(f"    llm_judge={score:.2f} | {reasoning[:80]}{review_flag}")

        return {
            "key": "soc_judge_score",
            "score": score,
            "comment": f"{reasoning} | expected={expected}, got={actual}",
        }

    return evaluator


# ---------------------------------------------------------------------------
# Human-in-the-loop: send borderline runs to annotation queue
# ---------------------------------------------------------------------------

def flag_for_human_review(results, experiment_name: str) -> None:
    """
    After an experiment run, push any run scoring below HUMAN_REVIEW_THRESHOLD
    to the LangSmith annotation queue for a human analyst to confirm.

    Args:
        results : EvaluationResults object returned by ls_evaluate().
        experiment_name: used only for the console log message.
    """
    client = Client()

    queues = list(client.list_annotation_queues(name=ANNOTATION_QUEUE_NAME))
    if not queues:
        print(
            f"  WARNING: Annotation queue '{ANNOTATION_QUEUE_NAME}' not found. "
            "Create it in LangSmith UI → Annotation Queues → + New Queue."
        )
        return

    queue_id = str(queues[0].id)
    flagged_run_ids: list[str] = []

    for row in list(results):
        eval_results = row.get("evaluation_results", {}).get("results", [])
        for r in eval_results:
            if (
                getattr(r, "key", None) == "soc_judge_score"
                and r.score is not None
                and r.score < HUMAN_REVIEW_THRESHOLD
            ):
                run = row.get("run")
                if run and hasattr(run, "id"):
                    flagged_run_ids.append(str(run.id))

    if not flagged_run_ids:
        print(f"  [{experiment_name}] All runs above threshold — no human review needed.")
        return

    try:
        client.add_runs_to_annotation_queue(queue_id, run_ids=flagged_run_ids)
        print(
            f"  [{experiment_name}] {len(flagged_run_ids)} run(s) scored < {HUMAN_REVIEW_THRESHOLD}"
            f" → sent to '{ANNOTATION_QUEUE_NAME}' for human confirmation."
        )
    except Exception as e:
        print(f"  WARNING: Could not add runs to annotation queue: {e}")
