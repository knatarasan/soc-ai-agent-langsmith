"""
Build and push the SOC triage benchmark dataset to LangSmith.

Creates a dataset named "soc-triage-benchmark" with 10 labeled examples
covering true positives, false positives, and ambiguous edge cases.

Usage:
    python dataset.py

After running, find the dataset at:
    https://smith.langchain.com → Datasets & Testing → soc-triage-benchmark
"""

import os
from dotenv import load_dotenv

load_dotenv()

if not os.getenv("LANGSMITH_API_KEY"):
    raise EnvironmentError(
        "LANGSMITH_API_KEY is not set. Copy .env.example to .env and fill in your key."
    )

from langsmith import Client  # noqa: E402

DATASET_NAME = "soc-triage-benchmark"

# ---------------------------------------------------------------------------
# 2 labeled examples
# ---------------------------------------------------------------------------

TEST_EXAMPLES = [
    # --- True Positives ---
    {
        "inputs": {
            "alert": "Internal host 192.168.1.105 making repeated DNS requests to known C2 domain bad-domain.xyz. 47 requests in 10 minutes.",
            "source_ip": "192.168.1.105",
            "rule": "C2 Communication Detected",
        },
        "outputs": {
            "decision": "true_positive",
            "severity": "critical",
            "reasoning": "Repeated DNS requests to a known C2 domain from an internal host is a strong indicator of compromise. Immediate escalation required.",
        },
    },
    # --- False Positives ---
    {
        "inputs": {
            "alert": "Port scan detected from 45.33.32.156. 8 ports probed.",
            "source_ip": "45.33.32.156",
            "rule": "Port Scan Detected",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "45.33.32.156 is Shodan's internet scanner. This is routine internet background noise, not targeted activity.",
        },
    },
    {
        "inputs": {
            "alert": "Outbound connection to 8.8.8.8 on port 53. Flagged by DNS monitoring rule.",
            "source_ip": "8.8.8.8",
            "rule": "Suspicious DNS Server Contact",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "8.8.8.8 is Google's public DNS server. This is expected legitimate DNS traffic, not suspicious activity.",
        },
    },
    # --- Ambiguous / Edge Cases ---
    {
        "inputs": {
            "alert": "SSH login attempt from 203.0.113.42. 2 failed attempts, then 1 success.",
            "source_ip": "203.0.113.42",
            "rule": "SSH Login Success After Failures",
        },
        "outputs": {
            "decision": "escalate",
            "severity": "medium",
            "reasoning": "Successful SSH login after failures from an unknown external IP is suspicious even at low volume. Could be credential stuffing with valid credentials found.",
        },
    },
]

# ---------------------------------------------------------------------------
# 10 labeled examples — 8 false_positive / 1 true_positive / 1 escalate.
#
# Real SOC alert streams run roughly 70-90% false positive (alert fatigue is
# the industry-standard complaint). A dataset that's a balanced three-way
# split doesn't test that problem. This one does: 80% of these alerts are
# routine benign infrastructure that happens to look alarming (CI/CD runners,
# backup jobs, package mirrors) unless you know what the source host is for.
#
# Every source_ip here has real backing data in tools.py — investigate_ip
# returns actual signal, not "Unknown" — so a correct call is something the
# agent can actually reason its way to, not guess.
# ---------------------------------------------------------------------------

EXAMPLES = [
    # --- True Positive (1) ---
    {
        "inputs": {
            "alert": "Internal host 192.168.10.45 beaconing to 91.195.240.117:4444 every ~2.7s. 312 events in 14 minutes.",
            "rule": "C2 Beacon Detected",
            "source_ip": "192.168.10.45",
            "destination_ip": "91.195.240.117",
            "destination_port": 4444,
            "event_count": 312,
            "timestamp": "2024-03-12T02:00:00Z",
            "severity": "critical",
        },
        "outputs": {
            "decision": "true_positive",
            "severity": "critical",
            "reasoning": "Internal host beaconing to a known C2 destination on port 4444, with 312 correlated events in 14 minutes. Confirmed compromise, immediate escalation.",
        },
    },
    # --- Escalate / genuinely ambiguous (1) ---
    {
        "inputs": {
            "alert": "SSH login from 203.0.113.42. 2 failed attempts, then 1 success.",
            "rule": "SSH Login Success After Failures",
            "source_ip": "203.0.113.42",
            "destination_ip": "10.0.0.10",
            "destination_port": 22,
            "event_count": 3,
            "timestamp": "2024-01-15T03:00:00Z",
            "severity": "medium",
        },
        "outputs": {
            "decision": "escalate",
            "severity": "medium",
            "reasoning": "Successful SSH login after failures from an unfamiliar external IP is suspicious even at low volume. Could be credential stuffing with valid creds. Needs human review.",
        },
    },
    # --- False Positives (8) — the realistic majority ---
    {
        "inputs": {
            "alert": "Port scan detected from 45.33.32.156. 8 ports probed.",
            "rule": "Port Scan Detected",
            "source_ip": "45.33.32.156",
            "destination_ip": "10.0.0.5",
            "destination_port": 22,
            "event_count": 8,
            "timestamp": "2024-01-15T10:00:00Z",
            "severity": "low",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "45.33.32.156 is Shodan's internet scanner. Routine internet background noise, not targeted activity.",
        },
    },
    {
        "inputs": {
            "alert": "Outbound connection to 8.8.8.8 on port 53. Flagged by DNS monitoring rule.",
            "rule": "Suspicious DNS Server Contact",
            "source_ip": "8.8.8.8",
            "destination_ip": "10.0.1.15",
            "destination_port": 53,
            "event_count": 1,
            "timestamp": "2024-01-15T09:00:00Z",
            "severity": "low",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "8.8.8.8 is Google's public DNS server. Expected legitimate DNS traffic, not suspicious activity.",
        },
    },
    {
        "inputs": {
            "alert": "Multiple failed logins from 10.0.0.55. 3 failures in 10 minutes.",
            "rule": "Failed Login Threshold Exceeded",
            "source_ip": "10.0.0.55",
            "destination_ip": "N/A",
            "destination_port": 0,
            "event_count": 3,
            "timestamp": "2024-01-15T08:00:00Z",
            "severity": "low",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "Only 3 failed attempts from an internal IP, below brute-force threshold. Likely a mistyped password.",
        },
    },
    {
        "inputs": {
            "alert": "Internal host 10.0.6.10 sent 400 outbound events to 52.206.34.133 over port 443.",
            "rule": "CI/CD Agent Outbound Traffic",
            "source_ip": "10.0.6.10",
            "destination_ip": "52.206.34.133",
            "destination_port": 443,
            "event_count": 400,
            "timestamp": "2024-03-15T05:30:00Z",
            "severity": "high",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "10.0.6.10 is a registered CI/CD build runner. 400 outbound events to an artifact registry over 443 matches its normal deployment schedule.",
        },
    },
    {
        "inputs": {
            "alert": "Internal host 10.0.7.20 sent 180 outbound events to 104.16.18.35 over port 443.",
            "rule": "Package Registry Traffic",
            "source_ip": "10.0.7.20",
            "destination_ip": "104.16.18.35",
            "destination_port": 443,
            "event_count": 180,
            "timestamp": "2024-03-14T14:00:00Z",
            "severity": "high",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "10.0.7.20 is a build host pulling dependencies from a public package registry. Expected recurring traffic for this asset.",
        },
    },
    {
        "inputs": {
            "alert": "Internal host 10.0.8.5 transferred 950 events to 34.120.10.20 over port 443 at 2 AM.",
            "rule": "Large Outbound Transfer Detected",
            "source_ip": "10.0.8.5",
            "destination_ip": "34.120.10.20",
            "destination_port": 443,
            "event_count": 950,
            "timestamp": "2024-03-16T02:00:00Z",
            "severity": "high",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "10.0.8.5 is the nightly backup host. Transfer matches its scheduled 2 AM backup window to an approved cloud storage endpoint.",
        },
    },
    {
        "inputs": {
            "alert": "140 requests to internal admin endpoints from 10.0.9.12 in 5 minutes.",
            "rule": "Web Application Scanning Detected",
            "source_ip": "10.0.9.12",
            "destination_ip": "10.0.1.50",
            "destination_port": 443,
            "event_count": 140,
            "timestamp": "2024-03-10T22:00:00Z",
            "severity": "medium",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "10.0.9.12 is the security team's own authorized vulnerability scanner, running its weekly scheduled scan.",
        },
    },
    {
        "inputs": {
            "alert": "Internal host 10.0.2.30 made 1200 outbound connections to 162.159.200.1 over port 443.",
            "rule": "Repeated External Connection",
            "source_ip": "10.0.2.30",
            "destination_ip": "162.159.200.1",
            "destination_port": 443,
            "event_count": 1200,
            "timestamp": "2024-03-15T08:00:00Z",
            "severity": "high",
        },
        "outputs": {
            "decision": "false_positive",
            "severity": "low",
            "reasoning": "10.0.2.30 is a monitoring agent sending routine health-check heartbeats. High event count reflects polling frequency, not exfiltration.",
        },
    },
]


def main() -> None:
    client = Client()

    print(f"Connecting to LangSmith...")
    print(f"Target dataset: '{DATASET_NAME}'")

    # Create dataset if it doesn't already exist. If it does, wipe its existing
    # examples first — otherwise reruns just append onto whatever was pushed
    # last time, and the dataset silently drifts out of sync with EXAMPLES.
    existing = list(client.list_datasets(dataset_name=DATASET_NAME))
    if existing:
        dataset = existing[0]
        old_examples = list(client.list_examples(dataset_id=dataset.id))
        if old_examples:
            print(f"Dataset already exists (id={dataset.id}). Removing {len(old_examples)} stale example(s)...")
            for ex in old_examples:
                client.delete_example(example_id=ex.id)
        else:
            print(f"Dataset already exists (id={dataset.id}), no existing examples.")
    else:
        dataset = client.create_dataset(
            dataset_name=DATASET_NAME,
            description=(
                "SOC triage benchmark: 10 labeled examples covering "
                "true positives, false positives, and ambiguous edge cases "
                "for evaluating SOC analyst agent accuracy."
            ),
        )
        print(f"Dataset created (id={dataset.id})")

    # Push examples
    inputs = [ex["inputs"] for ex in EXAMPLES]
    outputs = [ex["outputs"] for ex in EXAMPLES]

    client.create_examples(
        inputs=inputs,
        outputs=outputs,
        dataset_id=dataset.id,
    )

    print(f"\n✓ Pushed {len(EXAMPLES)} examples to '{DATASET_NAME}'")
    print(f"\nView dataset at:")
    print(f"  https://smith.langchain.com → Datasets & Testing → {DATASET_NAME}")


if __name__ == "__main__":
    main()
