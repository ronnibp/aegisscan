"""MITRE ATT&CK mapping.

Every finding produced by AegisScan carries ATT&CK technique IDs. This module
holds the technique catalogue used to render the ATT&CK matrix in the UI and
reports, plus helpers to normalise and aggregate mappings.

Coverage is scoped to the techniques that are actually relevant to the
vulnerability classes AegisScan detects (attacker entry paths enabled by the
weaknesses found), not the full framework.
"""

from __future__ import annotations

# Ordered as in the official ATT&CK Enterprise matrix.
TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0006", "Credential Access"),
    ("TA0003", "Persistence"),
    ("TA0002", "Execution"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

TECHNIQUES = {
    "T1595": {"name": "Active Scanning", "tactic": "TA0043",
              "desc": "Adversary probes the infrastructure for weaknesses before attacking."},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "TA0043",
                  "desc": "Adversary scans victims for vulnerabilities that can be exploited."},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "TA0043",
              "desc": "Adversary collects host information such as versions and roles."},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "TA0043",
              "desc": "Adversary collects identity information such as email addresses."},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001",
              "desc": "Adversary exploits a weakness in an internet-facing application."},
    "T1133": {"name": "External Remote Services", "tactic": "TA0001",
              "desc": "Adversary leverages externally-facing remote services (RDP, VPN, SSH) to gain access."},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001",
              "desc": "Adversary uses credentials of existing accounts to gain initial access."},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "TA0001",
              "desc": "Adversary compromises a dependency or component of the supply chain."},
    "T1552": {"name": "Unsecured Credentials", "tactic": "TA0006",
              "desc": "Adversary searches for credentials that are insecurely stored."},
    "T1552.001": {"name": "Credentials In Files", "tactic": "TA0006",
                  "desc": "Adversary searches for passwords and keys stored in files (.env, configs, source)."},
    "T1552.004": {"name": "Private Keys", "tactic": "TA0006",
                  "desc": "Adversary searches for private key material on compromised systems or in repositories."},
    "T1110": {"name": "Brute Force", "tactic": "TA0006",
              "desc": "Adversary guesses passwords via brute force when rate limiting/lockout is missing."},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006",
              "desc": "Adversary extracts credentials from password stores and vaults."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002",
              "desc": "Adversary abuses interpreters (shell, eval, deserialization) to execute code."},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "TA0002",
              "desc": "Adversary exploits client software vulnerabilities to execute code."},
    "T1505.003": {"name": "Web Shell", "tactic": "TA0003",
                  "desc": "Adversary backdoors a web server with a web shell (enabled by upload/RCE flaws)."},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "TA0008",
              "desc": "Adversary exploits vulnerable services to move laterally."},
    "T1021": {"name": "Remote Services", "tactic": "TA0008",
              "desc": "Adversary uses valid remote services (SSH, RDP, SMB) to move laterally."},
    "T1005": {"name": "Data from Local System", "tactic": "TA0009",
              "desc": "Adversary reads local files such as databases and configs."},
    "T1213": {"name": "Data from Information Repositories", "tactic": "TA0009",
              "desc": "Adversary pulls data from repositories (git, wikis, issue trackers)."},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010",
              "desc": "Adversary exfiltrates data over an existing command-and-control channel."},
    "T1565": {"name": "Data Manipulation", "tactic": "TA0040",
              "desc": "Adversary inserts, deletes or modifies data (e.g. via SQL injection)."},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "TA0006",
              "desc": "Adversary positions between two communicating parties; weak TLS enables interception."},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "TA0040",
              "desc": "Adversary exhausts a service (enabled by ReDoS / resource exhaustion flaws)."},
}

TACTIC_ORDER = {tid: i for i, (tid, _) in enumerate(TACTICS)}


def normalize(ids: list) -> list:
    """Keep only known technique ids, preserving order."""
    out = []
    for i in ids or []:
        i = i.strip().upper() if isinstance(i, str) else i
        if i in TECHNIQUES and i not in out:
            out.append(i)
    return out


def tactic_of(technique_id: str) -> str:
    t = TECHNIQUES.get(technique_id)
    return t["tactic"] if t else ""


def tactic_name(tactic_id: str) -> str:
    for tid, name in TACTICS:
        if tid == tactic_id:
            return name
    return tactic_id


def aggregate(findings: list) -> dict:
    """Build {tactic_id: {technique_id: [finding ids]}} from findings."""
    matrix: dict = {}
    for f in findings:
        for t in normalize(f.mitre):
            tac = tactic_of(t)
            if not tac:
                continue
            matrix.setdefault(tac, {}).setdefault(t, []).append(f.id)
    return {k: matrix[k] for k in sorted(matrix, key=lambda x: TACTIC_ORDER.get(x, 99))}


def tactics_covered(matrix: dict) -> list:
    return list(matrix.keys())
