"""
Multi-agent SOC pipeline built with LangGraph.

Every node is a plain Python function — no nested ReAct agents.
Tool calls are fixed and made directly in each node. A single LLM call
per node synthesizes the results.

  Supervisor    — routes and concludes. Pure routing logic, one LLM call to write verdict.
  Triage        — calls investigate_ip, then one LLM call to classify.
  Investigation — calls investigate_ip + search_elastic, then one LLM call to analyse.

Entry point: build_soc_graph() → compiled StateGraph.

LangSmith tracing is enabled automatically when LANGSMITH_TRACING=true and
LANGSMITH_API_KEY are set in the environment.
"""

from typing import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from tools import investigate_ip, search_elastic

# ---------------------------------------------------------------------------
# Shared graph state
# ---------------------------------------------------------------------------


class SOCState(TypedDict):
    alert: dict
    triage_result: str | None
    investigation_result: str | None
    final_verdict: str | None
    next_step: str


# ---------------------------------------------------------------------------
# Prompts
# Nodes call tools in Python now — prompts only describe how to reason,
# not which tools to call.
# ---------------------------------------------------------------------------


INVESTIGATION_PROMPT = """You are a SOC Investigation Agent. You have been given an alert,
the Triage Agent's findings, and results from Elasticsearch (activity summary + correlated
alert IDs). Analyse the evidence and produce a structured verdict.

Assess:
- Is the activity isolated to one host, or part of a broader pattern?
- Do the correlated alert IDs confirm a campaign or repeated behaviour?
- What is the blast radius?

If the scope exceeds automated resolution (e.g. active lateral movement across multiple hosts),
recommend escalate rather than guessing.

Respond in this exact format:
decision: true_positive | false_positive | escalate
severity: critical | high | medium | low
reasoning: 2-3 sentences with specific evidence from the data provided
related_alerts: comma-separated alert IDs found (or "none")
recommended_action: what the SOC should do next"""


SUPERVISOR_VERDICT_PROMPT = """You are a SOC Supervisor issuing the final verdict on a security alert.
You receive findings from Triage and optionally Investigation. Write a concise final verdict for the SOC Dashboard.

Respond in this exact format:
final_decision: true_positive | false_positive | escalate
severity: critical | high | medium | low
summary: 2-3 sentence narrative combining all findings
investigated_by: triage_only | triage_and_investigation
recommended_action: one-line action for the SOC analyst"""


TRIAGE_PROMPT = """You are a SOC Triage Agent. You have been given an alert and the IP lookup
results from threat intelligence and geolocation tools. Classify the alert as exactly one of:

  false_positive — close ONLY when ALL three are true:
      (a) IP is a known benign service (Google DNS, CDN, registered scanner like Shodan)
          OR an internal IP with zero SIEM alert history
      (b) Rule is a low-signal rule (port scan, health check, DNS, NTP, geo-anomaly)
      (c) Event count is low and consistent with normal background traffic

  needs_investigation — everything else: high-signal rule, high event count,
      external IP with any threat signals, or insufficient data to close confidently

CRITICAL: Internal IPs are NOT automatically false positives. An internal host is the
source in C2 beacon, ransomware, and lateral movement alerts because it IS the compromised
machine. If the rule includes C2, ransomware, lateral movement, brute force, or suspicious
outbound — classify as needs_investigation regardless of whether the IP is internal.

When in doubt, return needs_investigation. Do not guess.

Respond in this exact format:
decision: false_positive | needs_investigation
confidence: 0.0-1.0
reasoning: one-line explanation
indicators: comma-separated suspicious signals (leave blank if false_positive)"""


# Triage prompt variants for experiment.py — swap via build_soc_graph(triage_prompt=...).
# Both output false_positive | needs_investigation (triage scope only).
# The Supervisor issues the final verdict (true_positive / escalate / false_positive).

TRIAGE_PRECISE_PROMPT = """You are a precise SOC Triage Agent. You have been given an alert
and IP lookup results. Classify as exactly one of:

  false_positive — only if evidence is completely clear: known benign service (Google DNS,
      Shodan scanner, CDN) OR internal IP with zero alert history AND a low-signal rule.
  needs_investigation — any threat signal, any high-signal rule (C2, ransomware, brute force,
      lateral movement), or anything that cannot be closed with full confidence.

Be conservative. Analyst time is expensive — but a missed TP is worse.

Respond in this exact format:
decision: false_positive | needs_investigation
confidence: 0.0-1.0
reasoning: one-line explanation
indicators: comma-separated suspicious signals (leave blank if false_positive)"""


TRIAGE_CAUTIOUS_PROMPT = """You are a cautious SOC Triage Agent. You have been given an alert
and IP lookup results. Classify as exactly one of:

  false_positive — only if ALL of the following are true: well-known benign service,
      zero related SIEM alerts, event count under 10, and a trivially low-signal rule.
  needs_investigation — everything else. Any external IP, any unfamiliar pattern,
      any event count above 10, or any doubt at all.

When in doubt, escalate. A missed breach is worse than a false alarm.

Respond in this exact format:
decision: false_positive | needs_investigation
confidence: 0.0-1.0
reasoning: one-line explanation
indicators: comma-separated suspicious signals (leave blank if false_positive)"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_alert(alert: dict) -> str:
    return (
        f"Alert ID   : {alert['alert_id']}\n"
        f"Rule       : {alert['rule']}\n"
        f"Source IP  : {alert['source_ip']}\n"
        f"Destination: {alert.get('destination_ip', 'N/A')}:{alert.get('destination_port', 'N/A')}\n"
        f"Event count: {alert['event_count']}\n"
        f"Timestamp  : {alert['timestamp']}\n"
        f"Severity   : {alert['severity']}"
    )


# ---------------------------------------------------------------------------
# Graph — all nodes defined inline for locality
# ---------------------------------------------------------------------------


def build_soc_graph(triage_prompt: str = TRIAGE_PROMPT):
    """Build and compile the SOC pipeline as a StateGraph.

    Pass a different triage_prompt to swap the Triage Agent's reasoning strategy
    without changing the rest of the pipeline (used by experiment.py).
    """

    def supervisor_node(state: SOCState) -> dict:
        """Orchestrates the pipeline. No tool access.

        Stage 1 (no triage yet)      → route to triage.
        Stage 2 (triage done)        → route to investigation, or conclude if FP.
        Stage 3 (investigation done) → conclude with full context.
        """
        if state["triage_result"] is None:
            return {"next_step": "triage"}

        if state["investigation_result"] is None:
            decision_line = next(
                (
                    l
                    for l in state["triage_result"].splitlines()
                    if l.startswith("decision:")
                ),
                "",
            )
            if "needs_investigation" in decision_line:
                return {"next_step": "investigation"}
            llm = ChatOpenAI(model="gpt-4o", temperature=0)
            verdict = llm.invoke(
                f"{SUPERVISOR_VERDICT_PROMPT}\n\n"
                f"Alert:\n{_format_alert(state['alert'])}\n\n"
                f"Triage findings:\n{state['triage_result']}"
            )
            return {"next_step": "end", "final_verdict": verdict.content}

        llm = ChatOpenAI(model="gpt-4o", temperature=0)
        verdict = llm.invoke(
            f"{SUPERVISOR_VERDICT_PROMPT}\n\n"
            f"Alert:\n{_format_alert(state['alert'])}\n\n"
            f"Triage findings:\n{state['triage_result']}\n\n"
            f"Investigation findings:\n{state['investigation_result']}"
        )
        return {"next_step": "end", "final_verdict": verdict.content}

    def triage_node(state: SOCState) -> dict:
        """Fast first-pass: investigate_ip → one LLM call to classify."""
        source_ip = state["alert"]["source_ip"]
        ip_context = investigate_ip.invoke(source_ip)
        llm = ChatOpenAI(model="gpt-4o", temperature=0)
        response = llm.invoke(
            [
                SystemMessage(content=triage_prompt),
                HumanMessage(
                    content=(
                        f"Alert:\n{_format_alert(state['alert'])}\n\n"
                        f"IP lookup results:\n{ip_context}"
                    )
                ),
            ]
        )
        return {"triage_result": response.content}

    def investigation_node(state: SOCState) -> dict:
        """Deep analysis: investigate_ip + search_elastic → one LLM call to analyse."""
        source_ip = state["alert"]["source_ip"]
        ip_context = investigate_ip.invoke(source_ip)
        elastic_results = search_elastic.invoke(source_ip)
        llm = ChatOpenAI(model="gpt-4o", temperature=0)
        response = llm.invoke(
            [
                SystemMessage(content=INVESTIGATION_PROMPT),
                HumanMessage(
                    content=(
                        f"Alert:\n{_format_alert(state['alert'])}\n\n"
                        f"Triage findings:\n{state['triage_result']}\n\n"
                        f"IP lookup results:\n{ip_context}\n\n"
                        f"Elasticsearch results:\n{elastic_results}"
                    )
                ),
            ]
        )
        return {"investigation_result": response.content}

    def route_supervisor(state: SOCState) -> str:
        step = state["next_step"]
        return END if step == "end" else step

    graph = StateGraph(SOCState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("triage", triage_node)
    graph.add_node("investigation", investigation_node)
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_supervisor,
        {"triage": "triage", "investigation": "investigation", END: END},
    )
    graph.add_edge("triage", "supervisor")
    graph.add_edge("investigation", "supervisor")
    return graph.compile()
