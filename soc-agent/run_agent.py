"""
Run the multi-agent SOC pipeline on alerts from the feed.

To switch modes, edit main() manually:
    get_alerts_for_system_check() — one FP / ambiguous / TP to validate all branches
    get_alerts()                  — all alerts from the full feed

After it runs, open https://smith.langchain.com → Projects → soc-analyst-agent
to see the full trace: supervisor routing, triage tool calls, investigation tool calls.
"""

import os
from dotenv import load_dotenv

load_dotenv()

if not os.getenv("OPENAI_API_KEY"):
    raise EnvironmentError(
        "OPENAI_API_KEY is not set. Copy .env.example to .env and fill in your keys."
    )

if not os.getenv("LANGSMITH_API_KEY"):
    print("WARNING: LANGSMITH_API_KEY not set — traces will not be sent to LangSmith.")

from agent import build_soc_graph  # noqa: E402


def run_alert(alert: dict, graph) -> dict | None:
    """
    Run the full multi-agent pipeline on a single alert.
    Returns the final state dict (contains triage_result, investigation_result, final_verdict).
    """
    print(f"\n{'=' * 60}")
    print(f"Alert : {alert['alert_id']} | {alert['rule']}")
    print(
        f"IP    : {alert['source_ip']} | Events: {alert['event_count']} | Severity: {alert['severity']}"
    )
    print(f"{'=' * 60}")

    initial_state = {
        "alert": alert,
        "triage_result": None,
        "investigation_result": None,
        "final_verdict": None,
        "next_step": "",
    }

    print("\n[SUPERVISOR] Routing to Triage...")
    final_state = graph.invoke(initial_state)

    print("\n--- Triage Result ---")
    print(final_state.get("triage_result", "—"))

    if final_state.get("investigation_result"):
        print("\n--- Investigation Result ---")
        print(final_state["investigation_result"])

    print("\n--- Final Verdict ---")
    print(final_state.get("final_verdict", "—"))

    return final_state


def main() -> None:
    from feed_alerts import get_alerts, get_alerts_for_system_check

    # Switch between modes manually:
    #   get_alerts_for_system_check() — one FP / ambiguous / TP to validate all branches
    #   get_alerts()                  — all alerts from the full feed
    # alerts = get_alerts_for_system_check()
    alerts = get_alerts()

    graph = build_soc_graph()

    print(f"\nSOC PIPELINE — Processing {len(alerts)} alert(s)")
    for alert in alerts:
        run_alert(alert, graph)

    print("\n\nDone.")
    print("Traces: https://smith.langchain.com → Projects → soc-analyst-agent")


if __name__ == "__main__":
    main()
