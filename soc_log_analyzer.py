"""
SOC Log Analysis & Monitoring Tool
===================================
Academic Project - Security Operations Center
Parses system/auth logs, detects threats, and outputs a JSON security report.

Usage:
    python soc_log_analyzer.py                    # Analyze sample logs
    python soc_log_analyzer.py --file auth.log    # Analyze a real log file
    python soc_log_analyzer.py --generate 200     # Generate & analyze N fake logs
"""

import re
import json
import random
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ─── Configuration ────────────────────────────────────────────────────────────

THRESHOLDS = {
    "brute_force_attempts": 5,      # Failed logins from same IP in window
    "port_scan_ports": 10,           # Unique ports from same IP = port scan
    "ddos_requests_per_min": 100,    # Requests/min from single IP = DDoS
    "privilege_escalation_keywords": ["sudo", "su -", "chmod 777", "visudo"],
    "suspicious_ips": [              # Known bad IPs (demo list)
        "192.168.100.99", "10.0.0.254", "172.16.99.1"
    ],
}

SEVERITY_COLORS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}

# ─── Log Generator (for demo / testing) ───────────────────────────────────────

def generate_sample_logs(count: int = 100) -> list[dict]:
    """Generate realistic fake auth/system log entries."""
    users       = ["alice", "bob", "charlie", "root", "admin", "guest", "jenkins"]
    services    = ["sshd", "sudo", "apache2", "nginx", "postgresql", "vsftpd"]
    actions     = ["Accepted password", "Failed password", "session opened",
                   "session closed", "Invalid user", "Connection closed",
                   "Disconnected", "PAM authentication failure"]
    ips         = [f"192.168.1.{i}" for i in range(1, 20)] + \
                  ["10.0.0.1", "172.16.0.5"] + THRESHOLDS["suspicious_ips"]
    ports       = list(range(1024, 65535))

    logs = []
    base_time = datetime.now() - timedelta(hours=6)

    for i in range(count):
        ts      = base_time + timedelta(seconds=random.randint(0, 21600))
        ip      = random.choice(ips)
        user    = random.choice(users)
        service = random.choice(services)
        action  = random.choice(actions)
        port    = random.choice(ports)

        # Inject brute-force cluster on a specific attacker IP
        if i > count * 0.7 and random.random() < 0.4:
            ip     = "192.168.100.99"
            action = "Failed password"
            user   = "root"

        logs.append({
            "timestamp": ts.strftime("%b %d %H:%M:%S"),
            "hostname":  "server01",
            "service":   service,
            "action":    action,
            "user":      user,
            "ip":        ip,
            "port":      port,
        })

    return sorted(logs, key=lambda x: x["timestamp"])


# ─── Log Parser ───────────────────────────────────────────────────────────────

# Supports common auth.log / syslog patterns
AUTH_LOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<service>[^\[]+)(?:\[\d+\])?: (?P<message>.+)"
)

def parse_log_line(line: str) -> dict | None:
    m = AUTH_LOG_PATTERN.match(line.strip())
    if not m:
        return None
    msg     = m.group("message")
    ip      = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", msg)
    user    = re.search(r"(?:for|user) (\w+)", msg)
    port    = re.search(r"port (\d+)", msg)
    return {
        "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
        "hostname":  m.group("host"),
        "service":   m.group("service").strip(),
        "action":    msg[:60],
        "user":      user.group(1) if user else "unknown",
        "ip":        ip.group(1) if ip else "unknown",
        "port":      int(port.group(1)) if port else 0,
    }

def load_real_logs(filepath: str) -> list[dict]:
    entries = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
    print(f"[+] Parsed {len(entries)} log entries from {filepath}")
    return entries


# ─── Threat Detection Engine ──────────────────────────────────────────────────

class ThreatDetector:
    def __init__(self, logs: list[dict]):
        self.logs   = logs
        self.alerts = []

    def _alert(self, severity: str, category: str, description: str, ip: str = "", evidence: list = None):
        self.alerts.append({
            "severity":    severity,
            "category":    category,
            "description": description,
            "ip":          ip,
            "evidence":    evidence or [],
            "timestamp":   datetime.now().isoformat(),
        })

    # ── Rule 1: Brute Force Detection ────────────────────────────────────────
    def detect_brute_force(self):
        fail_map = defaultdict(list)
        for log in self.logs:
            if "Failed" in log["action"] or "failure" in log["action"].lower():
                fail_map[log["ip"]].append(log)

        for ip, attempts in fail_map.items():
            if len(attempts) >= THRESHOLDS["brute_force_attempts"]:
                users_targeted = list({a["user"] for a in attempts})
                severity = "CRITICAL" if len(attempts) > 20 else "HIGH"
                self._alert(
                    severity=severity,
                    category="Brute Force Attack",
                    description=f"{len(attempts)} failed login attempts from {ip} targeting users: {', '.join(users_targeted)}",
                    ip=ip,
                    evidence=[a["action"] for a in attempts[:3]],
                )

    # ── Rule 2: Port Scan Detection ───────────────────────────────────────────
    def detect_port_scan(self):
        port_map = defaultdict(set)
        for log in self.logs:
            if log["port"] > 0:
                port_map[log["ip"]].add(log["port"])

        for ip, ports in port_map.items():
            if len(ports) >= THRESHOLDS["port_scan_ports"]:
                self._alert(
                    severity="HIGH",
                    category="Port Scan",
                    description=f"Possible port scan from {ip} — {len(ports)} unique ports accessed",
                    ip=ip,
                    evidence=list(ports)[:10],
                )

    # ── Rule 3: Suspicious IP Activity ───────────────────────────────────────
    def detect_suspicious_ips(self):
        for log in self.logs:
            if log["ip"] in THRESHOLDS["suspicious_ips"]:
                self._alert(
                    severity="CRITICAL",
                    category="Known Malicious IP",
                    description=f"Activity from known malicious IP {log['ip']} — {log['action']}",
                    ip=log["ip"],
                    evidence=[log["action"]],
                )

    # ── Rule 4: Privilege Escalation ──────────────────────────────────────────
    def detect_privilege_escalation(self):
        for log in self.logs:
            for keyword in THRESHOLDS["privilege_escalation_keywords"]:
                if keyword in log["action"].lower() or keyword in log["service"].lower():
                    self._alert(
                        severity="HIGH",
                        category="Privilege Escalation",
                        description=f"Possible privilege escalation by '{log['user']}' from {log['ip']}",
                        ip=log["ip"],
                        evidence=[log["action"]],
                    )
                    break

    # ── Rule 5: Root Login Detection ─────────────────────────────────────────
    def detect_root_logins(self):
        for log in self.logs:
            if log["user"] == "root" and "Accepted" in log["action"]:
                self._alert(
                    severity="MEDIUM",
                    category="Root Login",
                    description=f"Direct root login accepted from {log['ip']}",
                    ip=log["ip"],
                    evidence=[log["action"]],
                )

    def run_all(self):
        print("[*] Running threat detection rules...")
        self.detect_brute_force()
        self.detect_port_scan()
        self.detect_suspicious_ips()
        self.detect_privilege_escalation()
        self.detect_root_logins()
        print(f"[+] Detection complete — {len(self.alerts)} alerts generated.")
        return self.alerts


# ─── Report Generator ─────────────────────────────────────────────────────────

def generate_report(logs: list[dict], alerts: list[dict]) -> dict:
    severity_counts = Counter(a["severity"] for a in alerts)
    category_counts = Counter(a["category"] for a in alerts)
    top_ips         = Counter(l["ip"] for l in logs).most_common(10)
    top_users       = Counter(l["user"] for l in logs).most_common(10)
    action_counts   = Counter(l["action"][:40] for l in logs).most_common(10)

    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool":         "SOC Log Analyzer v1.0",
            "total_logs":   len(logs),
            "total_alerts": len(alerts),
        },
        "summary": {
            "severity_distribution": dict(severity_counts),
            "alert_categories":      dict(category_counts),
            "risk_score":            _calculate_risk(severity_counts),
        },
        "top_source_ips":    [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_users":         [{"user": u, "count": c} for u, c in top_users],
        "top_actions":       [{"action": a, "count": c} for a, c in action_counts],
        "alerts":            alerts,
    }
    return report

def _calculate_risk(severity_counts: Counter) -> str:
    score = (severity_counts.get("CRITICAL", 0) * 10 +
             severity_counts.get("HIGH", 0)     * 5  +
             severity_counts.get("MEDIUM", 0)   * 2  +
             severity_counts.get("LOW", 0)      * 1)
    if score >= 30: return "CRITICAL"
    if score >= 15: return "HIGH"
    if score >= 5:  return "MEDIUM"
    return "LOW"


# ─── CLI Display ──────────────────────────────────────────────────────────────

def print_report(report: dict):
    meta    = report["report_metadata"]
    summary = report["summary"]

    print("\n" + "═" * 60)
    print("       SOC LOG ANALYSIS REPORT")
    print("═" * 60)
    print(f"  Generated : {meta['generated_at']}")
    print(f"  Log Entries: {meta['total_logs']}  |  Alerts: {meta['total_alerts']}")
    print(f"  Overall Risk Score: {SEVERITY_COLORS.get(summary['risk_score'], '')} {summary['risk_score']}")
    print("─" * 60)

    print("\n📊 SEVERITY DISTRIBUTION")
    for sev, count in summary["severity_distribution"].items():
        bar = "█" * count
        print(f"  {SEVERITY_COLORS[sev]} {sev:<12} {bar} ({count})")

    print("\n🚨 ALERTS")
    for alert in report["alerts"]:
        icon = SEVERITY_COLORS.get(alert["severity"], "⚪")
        print(f"\n  {icon} [{alert['severity']}] {alert['category']}")
        print(f"     {alert['description']}")
        if alert["evidence"]:
            print(f"     Evidence: {alert['evidence'][0]}")

    print("\n🔝 TOP SOURCE IPs")
    for entry in report["top_source_ips"][:5]:
        print(f"  {entry['ip']:<20} {entry['count']} events")

    print("\n" + "═" * 60)
    print("  Report saved to: soc_report.json")
    print("═" * 60 + "\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer")
    parser.add_argument("--file",     help="Path to a real log file (auth.log, syslog)")
    parser.add_argument("--generate", type=int, default=150,
                        help="Number of sample log entries to generate (default: 150)")
    parser.add_argument("--output",   default="soc_report.json", help="Output JSON report path")
    args = parser.parse_args()

    if args.file:
        logs = load_real_logs(args.file)
    else:
        print(f"[*] Generating {args.generate} sample log entries...")
        logs = generate_sample_logs(args.generate)

    detector = ThreatDetector(logs)
    alerts   = detector.run_all()

    report   = generate_report(logs, alerts)
    print_report(report)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Full JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()