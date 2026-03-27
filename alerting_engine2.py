#!/usr/bin/env python3
##################################################
# Module 4 Lab — Log & Threat Feed Alerting Engine
##################################################

import re, json, argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ── Tunable parameters ──────────────────────────────────────
BRUTE_THRESHOLD = 5       # failures before alerting
BRUTE_WINDOW    = 60      # seconds (Apache sliding window)

# ── File paths ───────────────────────────────────────────────
APACHE_LOG   = 'apache_access.log'
SYSLOG_LOG   = 'auth.log'
SURICATA_LOG = 'eve.json'
MISP_FEED    = 'misp_event.json'
STIX_FEED    = 'threat_bundle.json'
ALERTS_JSON  = 'alerts.json'   # <<< JSON output file

# IOC extractor class
from dataclasses import dataclass, field
from typing import ClassVar

@dataclass
class IOCExtractor:
    # Class variable: dict of { ioc_type: pattern_string }
    PATTERNS: ClassVar[dict] = {
        'ipv4':   r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
        'domain': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        'md5':    r'\b[a-fA-F0-9]{32}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'url':    r'\bhttps?://[^\s]+\b',
    }

    # Instance variable: compiled patterns
    _compiled: dict = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self):
        # compile each pattern with re.compile(v, re.IGNORECASE)
        for k, v in self.PATTERNS.items():
            self._compiled[k] = re.compile(v, re.IGNORECASE)

    def extract(self, text: str) -> dict[str, list[str]]:
        results = {}
        # for each compiled pattern, run findall()
        for k, pattern in self._compiled.items():
            matches = pattern.findall(text)
            # Deduplicate with set(), sort the results
            if matches:
                results[k] = sorted(set(matches))
        # Return only non-empty lists
        return results
    # OUTPUT
    # {'ipv4': ['198.51.100.17'], 'md5': ['d41d8cd98f00b204e9800998ecf8427e']}


########## STEP 2 ############
WANTED_TYPES = {'ip-dst', 'domain', 'md5', 'sha256', 'url', 'email-src'}

def load_misp(path: str) -> set[str]:
    iocs: set[str] = set()
    try:
        data = json.loads(open(path).read())
        for item in data.get('response', []):
            for attr in item.get('Event', {}).get('Attribute', []):
                if attr.get('type') in WANTED_TYPES:
                    iocs.add(attr['value'].lower())
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return iocs

# Extracts value from: [ipv4-addr:value = '1.2.3.4']
PATTERN_RE = re.compile(r"\[[\w:.-]+ = '([^']+)'\]")

def load_stix(path: str) -> set[str]:
    iocs: set[str] = set()
    try:
        bundle = json.loads(open(path).read())
        for obj in bundle.get('objects', []):
            if obj.get('type') != 'indicator':
                continue
            m = PATTERN_RE.search(obj.get('pattern', ''))
            if m:
                iocs.add(m.group(1).lower())
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return iocs

########## STEP 3 ############
def check_apache_bruteforce(logfile, alerts, verbose=False):  # <<< added verbose
    # named-group regex from Section 2.3
    pattern = re.compile(
        r'(?P<ip>[\d.]+) \S+ (?P<user>\S+) '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>\S+) HTTP/[\d.]+" '
        r'(?P<status>\d{3}) (?P<size>\d+|-)'
    )

    # Group timestamps by IP into a defaultdict(list)
    events = defaultdict(list)

    try:
        with open(logfile) as f:
            for line in f:
                m = pattern.match(line)
                if not m:
                    continue
                if verbose:  # <<< verbose print
                    print(f"[APACHE] Parsed line: {line.strip()}")
                if m.group('status') == '401':
                    ip = m.group('ip')
                    ts_str = m.group('timestamp')
                    ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                    events[ip].append(ts)
    except FileNotFoundError:
        return

    for ip, timestamps in events.items():
        timestamps.sort()
        for i in range(len(timestamps) - BRUTE_THRESHOLD + 1):
            start = timestamps[i]
            end = timestamps[i + BRUTE_THRESHOLD - 1]
            delta = (end - start).total_seconds()
            if delta <= BRUTE_WINDOW:
                alerts.append({
                    'source': 'apache',
                    'type': 'BRUTE_FORCE',
                    'detail': f'{ip} triggered brute force'
                })
                break


####### STEP 4 ###########
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3}) +(?P<day>\d+) (?P<time>[\d:]+) '
    r'(?P<host>\S+) (?P<proc>\S+?)(\[(?P<pid>\d+)\])?: '
    r'(?P<msg>.+)$'
)

SSH_FAIL   = re.compile(r'Failed password.*from (?P<ip>[\d.]+)')
NEW_USER   = re.compile(r'new user: name=(?P<name>\w+), UID=(?P<uid>\d+)')

def check_syslog_bruteforce(logfile, alerts, verbose=False):  # <<< added verbose
    fail_counts = defaultdict(int)
    try:
        with open(logfile) as f:
            for line in f:
                m = SYSLOG_RE.match(line)
                if not m:
                    continue
                if verbose:
                    print(f"[SYSLOG] Parsed line: {line.strip()}")
                entry = m.groupdict()
                msg = entry['msg']
                ssh_fail = SSH_FAIL.search(msg)
                if ssh_fail:
                    ip = ssh_fail.group('ip')
                    fail_counts[ip] += 1
                new_user = NEW_USER.search(msg)
                if new_user and new_user.group('uid') == '0':
                    alerts.append({
                        'source': 'syslog',
                        'type': 'NEW_ROOT_USER',
                        'detail': f"{new_user.group('name')} created with UID 0"
                    })
    except FileNotFoundError:
        return
    for ip, count in fail_counts.items():
        if count >= BRUTE_THRESHOLD:
            alerts.append({
                'source': 'syslog',
                'type': 'SSH_BRUTE_FORCE',
                'detail': f'{ip} — {count} SSH failures'
            })


####### STEP 5 ###########
def check_suricata(logfile, alerts, verbose=False):  # <<< added verbose
    try:
        with open(logfile) as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if verbose:
                    print(f"[SURICATA] Parsed line: {line.strip()}")
                if event.get('event_type') != 'alert':
                    continue
                alert = event.get('alert', {})
                if alert.get('severity') != 1:
                    continue
                src_ip = event.get('src_ip', 'unknown')
                dest_ip = event.get('dest_ip', 'unknown')
                dest_port = event.get('dest_port', 'unknown')
                signature = alert.get('signature', 'unknown')
                alerts.append({
                    'source': 'suricata',
                    'type': 'HIGH_SEV_ALERT',
                    'detail': f'{src_ip} -> {dest_ip}:{dest_port} | {signature}'
                })
    except FileNotFoundError:
        return

####### STEP 6 ###########
def check_ioc_matches(logfile, threat_iocs, source, alerts, verbose=False):  # <<< added verbose
    try:
        text = Path(logfile).read_text()
        if verbose:
            print(f"[IOC] Parsed file {logfile}: {text[:200]}...")  # show first 200 chars
    except FileNotFoundError:
        return
    extractor = IOCExtractor()
    extracted = extractor.extract(text)
    for ioc_type, values in extracted.items():
        for val in values:
            if val.lower() in threat_iocs:
                alerts.append({
                    'source': source,
                    'type': 'IOC_MATCH',
                    'detail': f'{ioc_type}={val} matched threat feed'
                })


########## STEP 7: MAIN FUNCTION ###########
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verbose', action='store_true', help='Print every parsed log line')  # <<< verbose flag
    args = parser.parse_args()

    extractor = IOCExtractor()
    threat_iocs = load_misp(MISP_FEED) | load_stix(STIX_FEED)
    print(f'Total threat IOCs loaded: {len(threat_iocs)}')

    alerts = []

    # Call all six check functions in order with verbose flag
    check_apache_bruteforce(APACHE_LOG, alerts, verbose=args.verbose)
    check_syslog_bruteforce(SYSLOG_LOG, alerts, verbose=args.verbose)
    check_suricata(SURICATA_LOG, alerts, verbose=args.verbose)
    check_ioc_matches(APACHE_LOG, threat_iocs, 'apache', alerts, verbose=args.verbose)
    check_ioc_matches(SYSLOG_LOG, threat_iocs, 'syslog', alerts, verbose=args.verbose)
    check_ioc_matches(SURICATA_LOG, threat_iocs, 'suricata', alerts, verbose=args.verbose)

    # Print alert report
    if not alerts:
        print('[OK] No alerts triggered.')
    else:
        print(f'[ALERTS] {len(alerts)} triggered:')
        for i, alert in enumerate(alerts, 1):
            print(f"{i}. Source: {alert['source']}, Type: {alert['type']}, Detail: {alert['detail']}")

    # <<< Export alerts to JSON file with ISO timestamp per alert
    for alert in alerts:
        alert['timestamp'] = datetime.now().isoformat()
    Path(ALERTS_JSON).write_text(json.dumps(alerts, indent=2))
    print(f"Alerts exported to {ALERTS_JSON}")

    # <<< Produce top-5 attacking IPs table
    import ipaddress

    ip_counts = defaultdict(int)
    for alert in alerts:
        # Extract IPs from alert['detail']
        matches = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', alert['detail'])
        for ip in matches:
            try:
                # Validate IP
                ipaddress.IPv4Address(ip)
                ip_counts[ip] += 1
            except ValueError:
                continue

    top5 = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print("\nTop 5 attacking IPs:")
    for ip, count in top5:
        print(f"{ip}: {count} alerts")


# 6Guarded entry point
if __name__ == '__main__':
    main()