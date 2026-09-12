# AegisScan — MITRE ATT&CK Mapping Reference

Every AegisScan finding carries the MITRE ATT&CK® Enterprise technique(s) that
an attacker could exercise **through the discovered weakness**. This is the
finding → technique reference used by the dashboard matrix and the reports.

## Tactics covered

| ID | Tactic | Typical AegisScan findings |
|---|---|---|
| TA0043 | Reconnaissance | open ports / fingerprintable services (T1595, T1592) |
| TA0001 | Initial Access | exploitable web flaws, vulnerable dependencies, exposed RDP/VPN (T1190, T1133, T1078, T1195) |
| TA0006 | Credential Access | hardcoded secrets, weak TLS, missing rate-limit protections (T1552.001, T1552.004, T1557) |
| TA0003 | Persistence | file-upload / RCE flaws enabling web shells (T1505.003) |
| TA0002 | Execution | eval/exec/command-injection/deserialization sinks (T1059, T1203) |
| TA0008 | Lateral Movement | exposed SMB/databases, remote-service exploits (T1210, T1021) |
| TA0009 | Collection | exposed files/repos/data stores (T1005, T1213) |
| TA0010 | Exfiltration | SSRF/CORS flaws usable as exfil channels (T1041) |
| TA0040 | Impact | SQL injection data manipulation, amplification-abusable memcached (T1565, T1499) |

## Technique details

| Technique | Name | Triggered by (examples) |
|---|---|---|
| T1595 / T1595.002 | Active Scanning / Vulnerability Scanning | web DAST module findings (attacker-equivalent recon surface), open-port attack surface |
| T1592 | Gather Victim Host Information | version-disclosing Server/X-Powered-By banners, SNMP |
| T1190 | Exploit Public-Facing Application | SQLi, XSS, command injection, SSRF, missing headers on public apps, exposed services |
| T1133 | External Remote Services | RDP/FTP/Telnet/VNC exposed, 0.0.0.0/0 security groups |
| T1078 | Valid Accounts | hardcoded passwords, missing branch protection (default-branch takeover) |
| T1195 | Supply Chain Compromise | vulnerable dependencies (SCA), `pull_request_target` workflow risks |
| T1552 / T1552.001 | Unsecured Credentials / Credentials In Files | hardcoded keys, committed `.env`, exposed `/.env` over web, plaintext pipeline secrets |
| T1552.004 | Private Keys | private key blocks/`.pem` files, weak crypto findings |
| T1557 | Adversary-in-the-Middle | weak TLS protocols/ciphers, no HSTS, `verify=False` in code, self-signed certs |
| T1059 | Command and Scripting Interpreter | `eval`/`exec`, `shell=True`, `child_process.exec`, PHP `system()` |
| T1203 | Exploitation for Client Execution | unsafe deserialization (pickle, PHP unserialize, Java ObjectInputStream, BinaryFormatter) |
| T1505.003 | Web Shell | unvalidated file-upload paths |
| T1210 | Exploitation of Remote Services | exposed MySQL/PostgreSQL/MSSQL/SMB |
| T1021 | Remote Services | exposed SMB/RDP lateral-movement paths |
| T1005 / T1213 | Data from Local System / Information Repositories | path traversal, exposed `.git`, public repo posture |
| T1041 | Exfiltration Over C2 Channel | permissive CORS reflection |
| T1565 | Data Manipulation | SQL injection findings |
| T1499 | Endpoint Denial of Service | exposed memcached, ReDoS-class sinks |

## How mapping works

- Each scanner rule declares its technique IDs inline (see `scanners/*.py`,
  the `mitre=[...]` lists).
- `core/mitre.normalize()` validates IDs against the catalogue; unknown IDs are
  dropped so reports never show phantom techniques.
- `core/mitre.aggregate(findings)` builds the tactic → technique → findings
  matrix used by the dashboard **MITRE ATT&CK** page and the HTML/Markdown
  reports.

> MITRE ATT&CK® is a registered trademark of The MITRE Corporation. AegisScan's
> mappings describe which attacker techniques a weakness *enables* — they do
> not imply any endorsement.
