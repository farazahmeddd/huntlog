# huntlog

CLI tool that parses Linux auth logs or Windows Security Event logs and flags suspicious activity. Built this because I wanted to understand what SIEM detection rules actually look like under the hood, without the $100k/yr Splunk license.

No dependencies beyond `rich` (optional, for colored output).

```
$ python huntlog.py --demo

  [CRITICAL]  Successful Login After Multiple Failures
  tactic:   Credential Access
  detail:   login for 'admin' from 185.234.100.55 after 8 failures
  response: Treat account as compromised. Disable it, rotate creds...

  [CRITICAL]  Root Login via SSH
  ...

  3 critical / 5 high / 5 medium
```

## setup

```bash
git clone https://github.com/yourusername/huntlog
cd huntlog
pip install rich   # optional but makes output way nicer
```

## usage

```bash
# run against built-in demo logs (no file needed)
python huntlog.py --demo
python huntlog.py --demo --log-type windows

# point it at a real log
python huntlog.py --file /var/log/auth.log
python huntlog.py --file security.csv --log-type windows

# export findings as JSON
python huntlog.py --demo --export findings.json

# see all rules
python huntlog.py --list-rules
```

## what it detects

| ID | Rule | Severity | MITRE |
|---|---|---|---|
| HL-001 | Brute Force Login (5+ failures, same IP) | High | T1110.001 |
| HL-002 | Successful Login After Multiple Failures | Critical | T1110.001 |
| HL-003 | Suspicious sudo Command | Medium | T1548.003 |
| HL-004 | New User Account Created | High | T1136.001 |
| HL-005 | Password Spray (many IPs, same username) | High | T1110.003 |
| HL-006 | Login Outside Business Hours | Medium | T1078 |
| HL-007 | Root Login via SSH | Critical | T1078.003 |
| HL-008 | Login from Known Tor/Proxy Exit Node | High | T1090 |
| HL-009 | RDP Login (Windows Logon Type 10) | Medium | T1021.001 |
| HL-010 | Account Lockout Storm | High | T1110 |

## how it works

There are four detection types, which map to how real SIEM rules work:

**threshold** -- fires when an event count crosses a limit. HL-001 fires if the same IP fails login more than 5 times. HL-005 fires if the same username gets hit from 3+ different IPs (that's a spray vs a brute force).

**pattern** -- fires on a single event matching specific fields. HL-007 fires any time there's a successful login where username is `root`.

**sequence** -- fires when event B happens after a prerequisite of event A. HL-002 fires on a successful login only if that same source IP had 3+ failures first.

**time_anomaly** -- fires on events in a specific time window. HL-006 flags logins between 10pm and 5am UTC.

All rules are Python dicts in the `RULES` list at the top of the file, so adding your own is pretty easy.

## getting real logs

**Linux:**
```bash
python huntlog.py --file /var/log/auth.log
# older systems might use /var/log/secure

# if using journald
journalctl _COMM=sshd --since "7 days ago" > sshd.log
python huntlog.py --file sshd.log
```

**Windows** (run PowerShell as admin):

The easiest way is to just run the included helper script, which exports the logs and runs huntlog in one shot:

```powershell
.\run_huntlog.ps1
```

If PowerShell blocks it with an execution policy error, run this first:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Or if you want to do it manually, here's the two-step version -- all in the same PowerShell window:

```powershell
# step 1: export logs to a csv
Get-WinEvent -LogName Security -MaxEvents 5000 | ForEach-Object {
    "$($_.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')),$($_.Id),$($_.Properties[5].Value),$($_.Properties[18].Value),$($_.Properties[8].Value)"
} | Out-File security.csv -Encoding utf8

# step 2: run huntlog against it
python huntlog.py --file security.csv --log-type windows
```

To also export findings as JSON:
```powershell
python huntlog.py --file security.csv --log-type windows --export findings.json
```

Native .evtx parsing would need python-evtx. The CSV export above works fine for most use cases.

## adding rules

```python
{
    "id": "HL-011",
    "name": "Your Rule Name",
    "mitre": "T1059.001",
    "tactic": "Execution",
    "severity": "high",          # critical / high / medium / low
    "applies_to": ["linux"],     # linux, windows, or both
    "type": "pattern",           # threshold, pattern, sequence, time_anomaly, ip_reputation
    "description": "What this catches and why it matters.",
    "match": {
        "event_type": "sudo",
        "command_pattern": r"your_regex",
    },
    "recommendation": "What to do when this fires.",
},
```

## why brute force and password spray are different rules

Brute force (HL-001) is one IP hammering one account many times. Password spray (HL-005) is many IPs each trying once against the same account. Spray is harder to catch with a simple count because no single IP crosses the threshold. Real SIEMs handle this with correlation rules that group differently, which is what HL-005 does.

## JSON output format

```json
{
  "generated": "2024-01-14T15:30:00",
  "event_count": 31,
  "finding_count": 8,
  "findings": [
    {
      "rule_id": "HL-002",
      "rule_name": "Successful Login After Multiple Failures",
      "severity": "critical",
      "mitre": "T1110.001",
      "tactic": "Credential Access",
      "detail": "login for 'admin' from 185.234.100.55 after 8 failures",
      ...
    }
  ]
}
```

## things to add eventually

- `--watch` mode to tail a live log file
- pull live Tor exit node list from check.torproject.org instead of the hardcoded set
- sigma rule import so you can use community detection rules
- GeoIP lookup on source IPs
- HTML report output
