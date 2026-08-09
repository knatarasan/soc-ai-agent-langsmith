"""
Simulated SOC tools — hardcoded responses so the demo runs without external dependencies.

Tool allocation per agent (LangChain uses each docstring to decide when to call):

  Triage Agent      → investigate_ip, threat_intel_lookup, enrich_ioc
  Investigation Agent → investigate_ip, threat_intel_lookup, enrich_ioc,
                        search_elastic (activity summary + correlated alert IDs)
  Supervisor Agent  → no tools

  create_ticket / escalate_alert are legacy tools kept for experiment.py only.
"""

import random
from langchain_core.tools import tool

# ---------------------------------------------------------------------------
# Simulated data stores
# ---------------------------------------------------------------------------

_ELASTIC_DATA = {
    "185.220.101.45": {
        "alert_count": 47,
        "alert_types": ["ssh_brute_force", "port_scan"],
        "first_seen": "2024-01-12T09:00:00Z",
        "last_seen": "2024-01-15T14:20:00Z",
        "active_days": 3,
    },
    "10.0.0.55": {
        "alert_count": 3,
        "alert_types": ["failed_login"],
        "first_seen": "2024-01-15T08:00:00Z",
        "last_seen": "2024-01-15T08:30:00Z",
        "active_days": 1,
    },
    "192.168.1.100": {
        "alert_count": 12,
        "alert_types": ["lateral_movement", "smb_enumeration"],
        "first_seen": "2024-01-15T12:00:00Z",
        "last_seen": "2024-01-15T14:00:00Z",
        "active_days": 1,
    },
    "8.8.8.8": {
        "alert_count": 0,
        "alert_types": [],
        "first_seen": None,
        "last_seen": None,
        "active_days": 0,
    },
    "45.33.32.156": {
        "alert_count": 8,
        "alert_types": ["port_scan"],
        "first_seen": "2024-01-15T10:00:00Z",
        "last_seen": "2024-01-15T13:00:00Z",
        "active_days": 1,
    },
    # TP-001: internal host compromised, beaconing to external C2 on port 4444
    "192.168.10.45": {
        "alert_count": 312,
        "alert_types": ["c2_beacon", "suspicious_outbound"],
        "first_seen": "2024-03-12T02:00:00Z",
        "last_seen": "2024-03-12T02:14:05Z",
        "active_days": 1,
    },
    # TP-002: internal host with ransomware file extension activity
    "10.0.5.77": {
        "alert_count": 1840,
        "alert_types": ["ransomware_extension", "mass_file_modification"],
        "first_seen": "2024-03-15T09:30:00Z",
        "last_seen": "2024-03-15T09:42:31Z",
        "active_days": 1,
    },
    # Realistic benign infra — long-standing, routine, low-signal history
    "10.0.6.10": {
        "alert_count": 6,
        "alert_types": ["outbound_data_transfer"],
        "first_seen": "2024-01-05T05:30:00Z",
        "last_seen": "2024-03-15T05:30:00Z",
        "active_days": 40,
    },
    "10.0.7.20": {
        "alert_count": 9,
        "alert_types": ["package_registry_traffic"],
        "first_seen": "2024-01-10T14:00:00Z",
        "last_seen": "2024-03-14T14:00:00Z",
        "active_days": 35,
    },
    "10.0.8.5": {
        "alert_count": 30,
        "alert_types": ["large_outbound_transfer"],
        "first_seen": "2023-12-01T02:00:00Z",
        "last_seen": "2024-03-16T02:00:00Z",
        "active_days": 90,
    },
    "10.0.9.12": {
        "alert_count": 4,
        "alert_types": ["web_application_scanning"],
        "first_seen": "2024-02-01T22:00:00Z",
        "last_seen": "2024-03-10T22:00:00Z",
        "active_days": 6,
    },
    "10.0.2.30": {
        "alert_count": 200,
        "alert_types": ["repeated_external_connection"],
        "first_seen": "2024-01-01T08:00:00Z",
        "last_seen": "2024-03-15T08:00:00Z",
        "active_days": 74,
    },
}

_THREAT_INTEL_DATA = {
    "185.220.101.45": {
        "is_malicious": True,
        "confidence_score": 95,
        "tags": ["tor_exit_node", "brute_force"],
        "source": "AbuseIPDB",
    },
    "192.168.1.100": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip"],
        "source": "Internal",
    },
    "45.33.32.156": {
        "is_malicious": False,
        "confidence_score": 10,
        "tags": ["scanner"],
        "source": "VirusTotal",
    },
    "8.8.8.8": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["google", "dns"],
        "source": "VirusTotal",
    },
    # TP-001/TP-002: internal IPs — not in external threat intel, but flagged internally
    "192.168.10.45": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "suspected_compromised"],
        "source": "Internal SIEM",
    },
    "10.0.5.77": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "suspected_compromised"],
        "source": "Internal SIEM",
    },
    # Realistic benign infra — registered assets, not threats
    "10.0.6.10": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "ci_cd_runner", "known_asset"],
        "source": "Internal CMDB",
    },
    "10.0.7.20": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "build_host", "known_asset"],
        "source": "Internal CMDB",
    },
    "10.0.8.5": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "backup_host", "known_asset"],
        "source": "Internal CMDB",
    },
    "10.0.9.12": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "security_scanner", "known_asset"],
        "source": "Internal CMDB",
    },
    "10.0.2.30": {
        "is_malicious": False,
        "confidence_score": 0,
        "tags": ["internal_ip", "monitoring_agent", "known_asset"],
        "source": "Internal CMDB",
    },
}

_RELATED_ALERTS_DATA = {
    "185.220.101.45": [
        {
            "alert_id": "ALERT-0041",
            "rule": "SSH Brute Force",
            "target": "10.0.0.5",
            "timestamp": "2024-01-15T11:00:00Z",
            "severity": "high",
        },
        {
            "alert_id": "ALERT-0038",
            "rule": "SSH Brute Force",
            "target": "10.0.0.8",
            "timestamp": "2024-01-15T10:30:00Z",
            "severity": "high",
        },
        {
            "alert_id": "ALERT-0029",
            "rule": "Port Scan Detected",
            "target": "10.0.0.0/24",
            "timestamp": "2024-01-15T09:00:00Z",
            "severity": "medium",
        },
    ],
    "192.168.1.100": [
        {
            "alert_id": "ALERT-0055",
            "rule": "SMB Enumeration",
            "target": "192.168.1.0/24",
            "timestamp": "2024-01-15T12:30:00Z",
            "severity": "high",
        },
        {
            "alert_id": "ALERT-0052",
            "rule": "Lateral Movement",
            "target": "192.168.1.110",
            "timestamp": "2024-01-15T12:10:00Z",
            "severity": "high",
        },
    ],
    "203.0.113.42": [
        {
            "alert_id": "ALERT-0061",
            "rule": "SSH Login Success After Failures",
            "target": "10.0.0.10",
            "timestamp": "2024-01-15T03:00:00Z",
            "severity": "medium",
        },
    ],
    "192.168.10.45": [
        {
            "alert_id": "ALERT-0071",
            "rule": "C2 Beacon Detected",
            "target": "91.195.240.117:4444",
            "timestamp": "2024-03-12T02:10:00Z",
            "severity": "critical",
        },
        {
            "alert_id": "ALERT-0068",
            "rule": "Suspicious Outbound Connection",
            "target": "91.195.240.117",
            "timestamp": "2024-03-12T01:55:00Z",
            "severity": "high",
        },
    ],
    "10.0.5.77": [
        {
            "alert_id": "ALERT-0080",
            "rule": "Mass File Modification",
            "target": "10.0.5.77 (local disk)",
            "timestamp": "2024-03-15T09:35:00Z",
            "severity": "critical",
        },
        {
            "alert_id": "ALERT-0078",
            "rule": "Ransomware File Extension Activity",
            "target": "10.0.5.77 (local disk)",
            "timestamp": "2024-03-15T09:30:00Z",
            "severity": "critical",
        },
    ],
}

_GEO_ASN_DATA = {
    "185.220.101.45": {
        "country": "Germany",
        "asn": "AS4134 Tor Network",
        "org": "Tor Exit Node",
    },
    "10.0.0.55": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network",
    },
    "192.168.1.100": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network",
    },
    "8.8.8.8": {
        "country": "US",
        "asn": "AS15169 Google LLC",
        "org": "Google",
    },
    "45.33.32.156": {
        "country": "US",
        "asn": "AS63949 Linode",
        "org": "Shodan.io",
    },
    "192.168.10.45": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — suspected compromised host",
    },
    "10.0.5.77": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — suspected compromised host",
    },
    "10.0.6.10": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — CI/CD build agent (ci-runner-03)",
    },
    "10.0.7.20": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — build/package host",
    },
    "10.0.8.5": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — nightly backup host",
    },
    "10.0.9.12": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — security team vulnerability scanner",
    },
    "10.0.2.30": {
        "country": "Internal",
        "asn": "Private",
        "org": "Internal Network — monitoring/health-check agent",
    },
}


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@tool
def search_elastic(source_ip: str, rule: str = "", time_window: str = "24h") -> str:
    """[Investigation Agent only] Query Elasticsearch for all activity from a source IP.
    Returns an activity summary (alert count, types, first/last seen) AND the specific
    correlated alert records (alert IDs, rules triggered, target hosts, severities).
    Optionally filter by rule name. Use this during deep investigation to assess how
    long and how broadly this IP has been active, and to get correlated alert IDs
    for the final report. Do not use during initial triage."""
    summary = _ELASTIC_DATA.get(source_ip)
    records = _RELATED_ALERTS_DATA.get(source_ip, [])

    if rule:
        records = [a for a in records if rule.lower() in a["rule"].lower()]

    if (summary is None or summary["alert_count"] == 0) and not records:
        return f"No Elasticsearch data found for {source_ip}."

    parts = []
    if summary and summary["alert_count"] > 0:
        parts.append(
            f"Activity summary: {summary['alert_count']} alerts | "
            f"types=[{', '.join(summary['alert_types'])}] | "
            f"first_seen={summary['first_seen']} | "
            f"last_seen={summary['last_seen']} | "
            f"active_days={summary['active_days']}"
        )

    if records:
        lines = [
            f"  {a['alert_id']} | {a['rule']} | target={a['target']} | {a['timestamp']} | severity={a['severity']}"
            for a in records
        ]
        parts.append(
            f"Correlated alerts (last {time_window}):\n"
            + "\n".join(lines)
            + f"\nTotal: {len(records)} correlated alert(s)"
        )

    return "\n\n".join(parts)


@tool
def threat_intel_lookup(source_ip: str) -> str:
    """[Triage + Investigation] Look up a source IP in threat intelligence databases
    (VirusTotal, AbuseIPDB). Returns malicious verdict, confidence score (0-100),
    tags, and source. Use this to determine if an IP is a known threat actor,
    Tor exit node, internet scanner, or benign service."""
    data = _THREAT_INTEL_DATA.get(
        source_ip,
        {
            "is_malicious": False,
            "confidence_score": 0,
            "tags": ["unknown"],
            "source": "No data",
        },
    )
    return (
        f"Threat intel for {source_ip}: "
        f"malicious={data['is_malicious']} | "
        f"confidence={data['confidence_score']}/100 | "
        f"tags=[{', '.join(data['tags'])}] | "
        f"source={data['source']}"
    )


@tool
def enrich_ioc(source_ip: str) -> str:
    """[Triage + Investigation] Enrich a source IP with geolocation and ASN context.
    Returns country, ASN, and hosting organization. Use this to determine whether
    an IP belongs to a datacenter, residential ISP, cloud provider, or known
    malicious infrastructure (e.g. Tor exit nodes)."""
    data = _GEO_ASN_DATA.get(
        source_ip,
        {
            "country": "Unknown",
            "asn": "Unknown",
            "org": "Unknown",
        },
    )
    return (
        f"IOC enrichment for {source_ip}: "
        f"country={data['country']} | "
        f"ASN={data['asn']} | "
        f"org={data['org']}"
    )


# @tool
# def create_ticket(title: str, severity: str, description: str, source_ip: str) -> str:
#     """[Legacy — not used by current pipeline] Create a security incident ticket in
#     Jira. In the current multi-agent pipeline, ticketing is a SOC Dashboard action
#     triggered after the Supervisor issues its final verdict, not an agent tool call."""
#     ticket_id = f"SOC-{random.randint(1000, 9999)}"
#     print(f"\n[TICKET CREATED] {ticket_id} → {title} | Severity: {severity}")
#     return f"Ticket {ticket_id} created: {title} | Severity: {severity} | Source IP: {source_ip}"


@tool
def escalate_alert(reason: str, source_ip: str, severity: str) -> str:
    """[Legacy — not used by current pipeline] Escalate an alert to Tier-2 analysts.
    In the current multi-agent pipeline, escalation is communicated via the
    Supervisor's final verdict to the SOC Dashboard, not as a direct agent tool call."""
    print(f"\n[ESCALATION] Tier-2 notified → {source_ip} | Severity: {severity}")
    return (
        f"ESCALATED to Tier-2 analyst. "
        f"Reason: {reason} | "
        f"IP: {source_ip} | "
        f"Severity: {severity}"
    )


@tool
def investigate_ip(source_ip: str) -> str:
    """[Triage + Investigation] Fast IP lookup combining threat intel reputation score
    and geo/ASN enrichment in a single call. Use this first on the source IP to
    establish whether it is known-malicious, a known scanner, or a benign service.
    Does not query alert history — use search_elastic for that (Investigation only)."""
    intel = threat_intel_lookup.invoke(source_ip)
    enriched = enrich_ioc.invoke(source_ip)
    return f"{intel}\n{enriched}"


# # Triage Agent: generic lookup tools only — no cross-alert correlation
# TRIAGE_TOOLS = [investigate_ip, threat_intel_lookup, enrich_ioc]

# Investigation Agent: all generic tools + Elasticsearch (summary + correlated alerts)
# INVESTIGATION_TOOLS = [
#     investigate_ip,
#     threat_intel_lookup,
#     search_elastic,
# ]

# Legacy: kept for experiment.py compatibility
# ALL_TOOLS = [investigate_ip, create_ticket, escalate_alert]
