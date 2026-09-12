"""Network service discovery — TCP connect scan with banner grabbing and
risky-service exposure checks (nmap-style, pure Python, no root required)."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.models import Finding, Severity

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 993, 995, 1080, 1433, 1521, 2049, 2181, 2375, 2376, 3000, 3306,
    3389, 3690, 4444, 5000, 5432, 5555, 5601, 5900, 5984, 6379, 6443, 6660,
    6667, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    11211, 27017, 27018, 28017, 50000, 50070, 61616,
]

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds (SMB)", 465: "smtps",
    587: "submission", 631: "ipp (CUPS)", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "ms-sql", 1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker API",
    2376: "docker API (TLS)", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
    3690: "svn", 4444: "metasploit-default", 5000: "http-alt/registry", 5432: "postgresql",
    5555: "adb", 5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes API", 6667: "irc", 8000: "http-dev", 8008: "http-alt",
    8009: "ajp (Tomcat)", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "sonar/php-fpm", 9090: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch-clusters", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb-shard", 28017: "mongodb-web", 50000: "sap", 50070: "hadoop-namenode",
    61616: "activemq",
}

# (ports, title, severity, description, remediation, mitre, cwe)
RISKY_SERVICES = [
    ((23,), "Telnet service exposed", Severity.HIGH,
     "Telnet transmits everything (including passwords) in cleartext.",
     "Disable Telnet entirely and use SSH with key authentication.",
     ["T1133"], "CWE-319"),
    ((21,), "FTP service exposed", Severity.MEDIUM,
     "Plain FTP sends credentials in cleartext and is a common entry point.",
     "Use SFTP/FTPS, or restrict FTP to an isolated, firewalled segment.",
     ["T1133"], "CWE-319"),
    ((3389,), "RDP exposed to the network", Severity.MEDIUM,
     "Exposed RDP is the top initial-access vector for ransomware (BlueKeep-class CVEs, brute force).",
     "Require VPN/bastion, enable NLA, enforce MFA and account lockout.",
     ["T1133", "T1021.1"], "CWE-287"),
    ((445, 139), "SMB exposed", Severity.MEDIUM,
     "Exposed SMB enables credential relay and eternal-blue-class exploitation on legacy systems.",
     "Block 445/139 at the perimeter; enforce SMBv3 with signing.",
     ["T1210", "T1021.002"], "CWE-284"),
    ((2375,), "Docker API without TLS exposed", Severity.CRITICAL,
     "The Docker Engine API on port 2375 is unauthenticated — root-equivalent remote code execution on the host.",
     "Bind to a unix socket, use 2376 with TLS client certs, and firewall it completely.",
     ["T1190"], "CWE-306"),
    ((6379,), "Redis exposed", Severity.HIGH,
     "Redis without authentication can be used to write files/cron and achieve RCE, and leaks data.",
     "Bind to localhost, set a strong requirepass/ACL, enable protected-mode.",
     ["T1190"], "CWE-306"),
    ((27017, 27018), "MongoDB exposed", Severity.HIGH,
     "Open MongoDB instances have leaked millions of records; unauthenticated by default when misconfigured.",
     "Enable auth, bind to internal interfaces and firewall.",
     ["T1190"], "CWE-306"),
    ((9200, 9300), "Elasticsearch exposed", Severity.MEDIUM,
     "Open Elasticsearch nodes leak all indexed data and allow scripted RCE on old versions.",
     "Enable x-pack security, bind internally, restrict via firewall.",
     ["T1190"], "CWE-306"),
    ((11211,), "Memcached exposed", Severity.MEDIUM,
     "Exposed memcached is abused for data theft and record-breaking UDP amplification DDoS.",
     "Bind to localhost with SASL auth; disable UDP.",
     ["T1499"], "CWE-306"),
    ((3306,), "MySQL exposed", Severity.MEDIUM,
     "Exposed databases enable credential brute-force and data theft.",
     "Bind to internal interfaces, least-privilege accounts, network ACLs.",
     ["T1210"], "CWE-284"),
    ((5432,), "PostgreSQL exposed", Severity.MEDIUM,
     "Exposed databases enable credential brute-force and data theft.",
     "listen_addresses on internal interfaces, pg_hba restrictions, network ACLs.",
     ["T1210"], "CWE-284"),
    ((5900,), "VNC exposed", Severity.HIGH,
     "VNC commonly has weak or no authentication and gives full desktop control.",
     "Tunnel VNC through SSH/VPN and set strong authentication.",
     ["T1133"], "CWE-287"),
    ((161,), "SNMP exposed", Severity.LOW,
     "SNMPv1/v2c uses community strings sent in cleartext and leaks host inventory.",
     "Use SNMPv3 with authPriv, restrict to management hosts.",
     ["T1592"], "CWE-319"),
    ((1433,), "Microsoft SQL Server exposed", Severity.MEDIUM,
     "Exposed MSSQL is brute-forced for sa/xp_cmdshell RCE paths.",
     "Hide behind firewall, disable xp_cmdshell, strong sa password.",
     ["T1210"], "CWE-284"),
    ((6443, 10250), "Kubernetes API exposed", Severity.MEDIUM,
     "An exposed K8s API without strict RBAC/authn enables cluster takeover.",
     "Restrict to control-plane/VPN CIDRs, enforce RBAC and audit logging.",
     ["T1190"], "CWE-306"),
    ((4444, 5555), "Suspicious listener (metasploit/adb default port)", Severity.MEDIUM,
     "A service is listening on a default exploitation/debug port; verify this is intentional.",
     "Identify and close the listener; firewall debug ports.",
     ["T1190"], "CWE-284"),
]


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256)
                return banner.decode("utf-8", "replace").strip()
            except (socket.timeout, ConnectionResetError, OSError):
                # some services (http) wait for a request; send a benign probe
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    return s.recv(256).decode("utf-8", "replace").strip()
                except (socket.timeout, ConnectionResetError, OSError):
                    return ""
    except (socket.timeout, OSError):
        return ""


def scan(host: str, ports: str = "top100", timeout: float = 1.5, max_threads: int = 200, progress=None):
    """Returns (open_ports: list[dict], findings: list[Finding])."""
    port_list = _parse_ports(ports)
    open_ports: list[dict] = []
    total = len(port_list)
    done = 0

    def check(p: int):
        nonlocal done
        try:
            with socket.create_connection((host, p), timeout=timeout) as s:
                s.settimeout(0.5)
                return p
        except (socket.timeout, OSError):
            return None

    with ThreadPoolExecutor(max_workers=min(max_threads, max(1, len(port_list)))) as pool:
        futures = {pool.submit(check, p): p for p in port_list}
        for fut in as_completed(futures):
            done += 1
            if progress and done % 20 == 0:
                progress(done, total)
            p = fut.result()
            if p is not None:
                banner = _grab_banner(host, p)
                open_ports.append({"port": p, "service": SERVICE_NAMES.get(p, "unknown"),
                                   "banner": banner[:200]})
    if progress:
        progress(total, total)

    open_ports.sort(key=lambda x: x["port"])
    findings: list[Finding] = []
    for risky in RISKY_SERVICES:
        rports, title, sev, desc, fix, mitre, cwe = risky
        hits = [o for o in open_ports if o["port"] in rports]
        if not hits:
            continue
        if not desc:
            continue
        for o in hits:
            findings.append(Finding(
                scanner="network", category="Exposed Service", title=title,
                severity=sev, target=host, location=f"{host}:{o['port']} ({o['service']})",
                description=desc + (f" Banner: {o['banner']}" if o["banner"] else ""),
                evidence=f"TCP {o['port']} open" + (f", banner: {o['banner'][:120]}" if o["banner"] else ""),
                remediation=fix, references=["https://www.cisecurity.org/insights/white-papers"],
                mitre=list(mitre), cwe=cwe, tags=["network", "exposure"],
            ))
    if open_ports:
        findings.append(Finding(
            scanner="network", category="Attack Surface",
            title=f"{len(open_ports)} TCP port(s) open on {host}",
            severity=Severity.INFO, target=host,
            location=host,
            description="Open ports form the reachable attack surface. Review each service for necessity and patch level.",
            evidence=", ".join(f"{o['port']}/{o['service']}" for o in open_ports[:15]),
            remediation="Close or firewall any service not required; keep required services patched and monitored.",
            references=[], mitre=["T1595", "T1133"], cwe="", score=0.0,
            tags=["network", "info"],
        ))
    return open_ports, findings


def _parse_ports(spec: str) -> list:
    spec = (spec or "top100").strip().lower()
    out: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part == "top100":
            out.update(TOP_100_PORTS)
        elif "-" in part:
            a, _, b = part.partition("-")
            out.update(range(int(a), int(b) + 1))
        else:
            try:
                out.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in out if 1 <= p <= 65535)
