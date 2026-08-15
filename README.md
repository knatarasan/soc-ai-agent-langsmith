# soc-ai-agent-langsmith

A multi-agent SOC (Security Operations Center) alert-triage pipeline built with
LangGraph + OpenAI, instrumented end-to-end with LangSmith for tracing,
datasets, experiments, LLM-as-judge evaluation, and human-in-the-loop review.

All security tooling is simulated (hardcoded lookup tables in
[tools.py](soc-agent/tools.py)) — no SIEM, Elasticsearch, or threat-intel
subscription is required to run the demo.

---

## Pipeline

```
SIEM (HIGH severity alerts)
        │
        ▼
   Supervisor ──► Triage ──► Supervisor ──► Investigation ──► Supervisor ──► Final verdict
                    │                                              │
              false_positive ──────────────────────────────────────┘
              (closed early, investigation skipped)
```

| Node              | What it does                                                | Tools called                       |
| ----------------- | ----------------------------------------------------------- | ---------------------------------- |
| **Supervisor**    | Pure routing logic; one LLM call to write the final verdict | none                               |
| **Triage**        | Classifies `false_positive` vs `needs_investigation`        | `investigate_ip`                   |
| **Investigation** | Deep analysis of scope / blast radius / correlated alerts   | `investigate_ip`, `search_elastic` |

Every node is a plain Python function with fixed tool calls — no nested ReAct
agents — so traces stay readable in LangSmith.

## Repository layout

| File                                                 | Purpose                                                                                                                                       |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| [agent.py](soc-agent/agent.py)                       | `build_soc_graph()` — the LangGraph pipeline + all prompts (incl. the `TRIAGE_PRECISE_PROMPT` / `TRIAGE_CAUTIOUS_PROMPT` experiment variants) |
| [tools.py](soc-agent/tools.py)                       | Simulated threat intel, geo/ASN enrichment, and Elasticsearch lookups                                                                         |
| [feed_alerts.py](soc-agent/feed_alerts.py)           | 20 labeled alerts (2 TP / 16 FP / 2 ambiguous) used by `run_agent.py`                                                                         |
| [run_agent.py](soc-agent/run_agent.py)               | Runs the pipeline over the alert feed and prints verdicts                                                                                     |
| [dataset.py](soc-agent/dataset.py)                   | Pushes the 10-example `soc-triage-benchmark` dataset to LangSmith                                                                             |
| [experiment.py](soc-agent/experiment.py)             | Runs the prompt-strategy experiment matrix against that dataset                                                                               |
| [evaluator.py](soc-agent/evaluator.py)               | LLM-as-judge evaluator + annotation-queue flagging (imported by `experiment.py`)                                                              |
| [demo/agent_graph.md](soc-agent/demo/agent_graph.md) | Mermaid architecture diagrams                                                                                                                 |

---

## Setup

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure `.env` for LangSmith

Copy the template and fill it in. The `.env` file lives at the **repository
root** and is git-ignored:

```bash
cp .env.example .env
```

```dotenv
LANGSMITH_TRACING=true
LANGSMITH_ENDPOINT=https://api.smith.langchain.com
LANGSMITH_API_KEY=lsv2_pt_xxxxxxxxxxxxxxxxxxxxxxxx
LANGSMITH_PROJECT=soc-agent

OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

| Variable             | Required                               | How to fill it                                                                                                                                             |
| -------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LANGSMITH_TRACING`  | yes                                    | `true` to send traces, `false` to run the pipeline with no tracing                                                                                         |
| `LANGSMITH_ENDPOINT` | yes                                    | `https://api.smith.langchain.com` for the US region; use `https://eu.api.smith.langchain.com` if your LangSmith workspace is in the EU                     |
| `LANGSMITH_API_KEY`  | yes for `dataset.py` / `experiment.py` | [smith.langchain.com](https://smith.langchain.com) → Settings → API Keys → **Create API Key**. Starts with `lsv2_pt_`                                      |
| `LANGSMITH_PROJECT`  | yes                                    | Any project name — it is created automatically on the first trace. Use `soc-analyst-agent` to match the links printed by `run_agent.py`                    |
| `OPENAI_API_KEY`     | yes                                    | [platform.openai.com](https://platform.openai.com/api-keys) → **Create new secret key**. Needs access to `gpt-4o` (pipeline) and `gpt-4o-mini` (LLM judge) |

Notes:

- `run_agent.py` hard-fails if `OPENAI_API_KEY` is missing and only warns if
  `LANGSMITH_API_KEY` is missing (it will just run untraced).
- `dataset.py` and `experiment.py` hard-fail without `LANGSMITH_API_KEY`,
  because they read and write LangSmith datasets.
- Never commit `.env` — it is already listed in [.gitignore](.gitignore).

### 3. Working directory

The modules import each other flatly (`from agent import ...`,
`from tools import ...`), so **run everything from inside `soc-agent/`**:

```bash
cd soc-agent
```

---

## Running the modules

### `run_agent.py` — run the pipeline over the alert feed

```bash
cd soc-agent
python run_agent.py
```

Processes all 20 alerts from [feed_alerts.py](soc-agent/feed_alerts.py) and
prints, per alert: the triage result, the investigation result (only when triage
escalated), and the supervisor's final verdict.

To do a quick 3-alert smoke test of every branch (one false positive, one
ambiguous, one true positive) instead of the full feed, edit `main()` in
[run_agent.py:70-71](soc-agent/run_agent.py#L70-L71) and swap the commented
lines:

```python
alerts = get_alerts_for_system_check()   # 3 alerts — one per category
# alerts = get_alerts()                  # all 20
```

`get_alerts(n=5)` also works if you just want the first N.

Traces: [smith.langchain.com](https://smith.langchain.com) → **Projects** →
your `LANGSMITH_PROJECT`.

### `dataset.py` — push the benchmark dataset to LangSmith

```bash
cd soc-agent
python dataset.py
```

Creates (or refreshes) a LangSmith dataset named **`soc-triage-benchmark`** with
10 labeled examples — 1 true positive, 1 escalate, 8 false positives, matching
the false-positive-heavy skew of a real alert stream.

Reruns are idempotent: if the dataset already exists, its current examples are
deleted before the `EXAMPLES` list is pushed again, so the dataset never drifts
out of sync with the file. Edit `EXAMPLES` in
[dataset.py:100](soc-agent/dataset.py#L100) and rerun to change the benchmark.

Run this **before** `experiment.py` — the experiment reads this dataset by name.

View at: **Datasets & Experiments** → `soc-triage-benchmark`.

### `experiment.py` — run the prompt-strategy experiment

```bash
cd soc-agent
python experiment.py
```

Runs the full pipeline over every dataset example twice, once per triage prompt
strategy:

| Experiment          | Triage prompt                                               |
| ------------------- | ----------------------------------------------------------- |
| `pipeline_precise`  | `TRIAGE_PRECISE_PROMPT` — closes FPs when evidence is clear |
| `pipeline_cautious` | `TRIAGE_CAUTIOUS_PROMPT` — escalates on any doubt           |

Everything else in the pipeline is held constant, so the score difference is
attributable to the triage strategy alone.

Three scorers run on each experiment:

- **`decision_match`** — exact string match against the expected label.
- **`soc_judge_score`** — `gpt-4o-mini` LLM-as-judge (0.0–1.0) that treats
  `escalate` and `true_positive` as equally valid for a confirmed threat, which
  exact match cannot.
- **`baseline_always_fp`** — a summary scorer reporting what "always guess
  false_positive, zero reasoning" would score on this dataset. Because the data
  is 80% FP, this baseline is high on purpose: an agent's accuracy only means
  something next to it.

Runs scoring below `HUMAN_REVIEW_THRESHOLD` (0.75, in
[evaluator.py:25](soc-agent/evaluator.py#L25)) are pushed to a LangSmith
annotation queue named **`SOC-AGENT-annotation-queue`**. Create it first in the
UI (**Annotation Queues → + New Queue**) — without it the script prints a
warning and continues.

Results land in **Datasets & Experiments → soc-triage-benchmark → Experiments**;
use **+ Compare** to see the two strategies side by side. A summary table is
also printed to the terminal.

---

## Typical first run

```bash
source .venv/bin/activate
cd soc-agent

python run_agent.py     # see the pipeline work, check traces in LangSmith
python dataset.py       # push the benchmark
python experiment.py    # compare the two triage strategies
```

## Cost note

Every alert costs at least two `gpt-4o` calls (triage + supervisor verdict), and
three when investigation runs. `experiment.py` multiplies that by 10 examples ×
2 strategies, plus one `gpt-4o-mini` judge call per row. Start with
`get_alerts_for_system_check()` in `run_agent.py` while you are validating your
setup.
