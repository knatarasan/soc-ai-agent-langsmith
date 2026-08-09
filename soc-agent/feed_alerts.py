"""
Alert feed for SOC agent testing.

20 labeled alerts — all HIGH or CRITICAL severity, matching the pipeline's
intake filter. Realistic SOC distribution:
  - 2  True Positives  (10%) — confirmed threats requiring action
  - 16 False Positives (80%) — benign/expected traffic triggering rules
  - 2  Ambiguous       (10%) — borderline cases needing human review

Usage:
    from feed_alerts import get_alerts, get_alerts_for_system_check
    alerts = get_alerts()                  # all 20
    alerts = get_alerts(n=5)              # first 5
    alerts = get_alerts_for_system_check() # 3 alerts — one per category
"""

_ALERTS = [
    # ------------------------------------------------------------------
    # TRUE POSITIVES (2)
    # ------------------------------------------------------------------
    {
        "alert_id": "TP-001",
        "rule": "C2 Beacon Detected",
        "source_ip": "192.168.10.45",
        "destination_ip": "91.195.240.117",
        "destination_port": 4444,
        "event_count": 312,
        "timestamp": "2024-03-12T02:14:05Z",
        "severity": "critical",
        "category": "true_positive",
    },
    {
        "alert_id": "TP-002",
        "rule": "Ransomware File Extension Activity",
        "source_ip": "10.0.5.77",
        "destination_ip": "10.0.5.77",
        "destination_port": 0,
        "event_count": 1840,
        "timestamp": "2024-03-15T09:42:31Z",
        "severity": "critical",
        "category": "true_positive",
    },
    # ------------------------------------------------------------------
    # FALSE POSITIVES (16)
    # ------------------------------------------------------------------
    {
        "alert_id": "FP-001",
        "rule": "Port Scan Detected",
        "source_ip": "45.33.32.156",
        "destination_ip": "203.0.113.10",
        "destination_port": 80,
        "event_count": 22,
        "timestamp": "2024-03-10T11:05:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-002",
        "rule": "Suspicious DNS Server Contact",
        "source_ip": "10.0.1.15",
        "destination_ip": "8.8.8.8",
        "destination_port": 53,
        "event_count": 45,
        "timestamp": "2024-03-10T12:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-003",
        "rule": "Large Outbound Transfer",
        "source_ip": "10.0.2.30",
        "destination_ip": "13.107.42.14",
        "destination_port": 443,
        "event_count": 1,
        "timestamp": "2024-03-11T08:30:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-004",
        "rule": "Unusual Outbound Port",
        "source_ip": "10.0.3.11",
        "destination_ip": "216.239.35.4",
        "destination_port": 123,
        "event_count": 6,
        "timestamp": "2024-03-11T00:00:05Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-005",
        "rule": "Large Outbound Download",
        "source_ip": "10.0.1.50",
        "destination_ip": "199.232.194.172",
        "destination_port": 443,
        "event_count": 3,
        "timestamp": "2024-03-11T03:15:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-006",
        "rule": "Internal Port Scan",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.0/24",
        "destination_port": 443,
        "event_count": 254,
        "timestamp": "2024-03-12T10:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-007",
        "rule": "Geo-Blocked IP Access",
        "source_ip": "104.16.132.229",
        "destination_ip": "10.0.8.1",
        "destination_port": 443,
        "event_count": 890,
        "timestamp": "2024-03-12T14:22:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-008",
        "rule": "Repeated Health Check Requests",
        "source_ip": "52.94.236.248",
        "destination_ip": "10.0.8.20",
        "destination_port": 80,
        "event_count": 720,
        "timestamp": "2024-03-13T06:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-009",
        "rule": "External IP Outbound Connection",
        "source_ip": "10.0.4.88",
        "destination_ip": "140.82.114.4",
        "destination_port": 443,
        "event_count": 55,
        "timestamp": "2024-03-13T09:45:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-010",
        "rule": "Failed Login Threshold Exceeded",
        "source_ip": "10.0.1.99",
        "destination_ip": "10.0.0.10",
        "destination_port": 389,
        "event_count": 4,
        "timestamp": "2024-03-13T08:55:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-011",
        "rule": "ICMP Flood Detected",
        "source_ip": "10.0.0.3",
        "destination_ip": "10.0.0.0/24",
        "destination_port": 0,
        "event_count": 254,
        "timestamp": "2024-03-14T07:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-012",
        "rule": "Geo-Anomaly: US Host Connecting to EU IP",
        "source_ip": "10.0.2.55",
        "destination_ip": "40.101.90.10",
        "destination_port": 443,
        "event_count": 230,
        "timestamp": "2024-03-14T10:10:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-013",
        "rule": "Package Registry Traffic",
        "source_ip": "10.0.4.22",
        "destination_ip": "104.16.18.35",
        "destination_port": 443,
        "event_count": 180,
        "timestamp": "2024-03-14T14:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-014",
        "rule": "CI/CD Agent Outbound Traffic",
        "source_ip": "10.0.6.10",
        "destination_ip": "52.206.34.133",
        "destination_port": 443,
        "event_count": 400,
        "timestamp": "2024-03-15T05:30:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-015",
        "rule": "Repeated External Connection",
        "source_ip": "10.0.8.1",
        "destination_ip": "162.159.200.1",
        "destination_port": 443,
        "event_count": 1200,
        "timestamp": "2024-03-15T08:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    {
        "alert_id": "FP-016",
        "rule": "High-Volume Video Streaming",
        "source_ip": "10.0.1.77",
        "destination_ip": "170.114.52.2",
        "destination_port": 443,
        "event_count": 3600,
        "timestamp": "2024-03-15T14:00:00Z",
        "severity": "high",
        "category": "false_positive",
    },
    # ------------------------------------------------------------------
    # AMBIGUOUS (2)
    # ------------------------------------------------------------------
    {
        "alert_id": "AMB-001",
        "rule": "SSH Login Success After Failures",
        "source_ip": "197.234.240.82",
        "destination_ip": "10.0.0.15",
        "destination_port": 22,
        "event_count": 7,
        "timestamp": "2024-03-14T23:47:00Z",
        "severity": "high",
        "category": "ambiguous",
    },
    {
        "alert_id": "AMB-002",
        "rule": "Unusual Outbound Data Volume",
        "source_ip": "10.0.3.40",
        "destination_ip": "35.186.224.25",
        "destination_port": 443,
        "event_count": 1,
        "timestamp": "2024-03-15T01:15:00Z",
        "severity": "high",
        "category": "ambiguous",
    },
]


def get_alerts_for_system_check() -> list[dict]:
    """
    Return one representative alert from each category for pipeline validation.

    Always returns exactly 3 alerts:
        [0] false_positive  — should be closed by Triage without escalation
        [1] ambiguous       — should be escalated to Investigation by Triage
        [2] true_positive   — should reach Investigation and return a true_positive verdict

    Use this to verify the full pipeline branches correctly end-to-end.
    """
    categories = ["false_positive", "ambiguous", "true_positive"]
    result = []
    for category in categories:
        alert = next((a for a in _ALERTS if a["category"] == category), None)
        if alert:
            result.append(alert)
    return result


def get_alerts(n: int | None = None) -> list[dict]:
    """
    Return alerts from the feed.

    Args:
        n: Maximum number of alerts to return. None returns all 20.

    Returns:
        List of alert dicts, capped at n if provided.
    """
    alerts = list(_ALERTS)
    return alerts[:n] if n is not None else alerts
