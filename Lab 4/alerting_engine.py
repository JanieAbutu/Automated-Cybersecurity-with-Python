#!/usr/bin/env python3
"""
Module 4 Lab — Log & Threat Feed Alerting Engine
"""

import re, json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from dataclasses import dataclass, field
from typing import ClassVar

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

########## STEP 1 ############
# IOC extractor class
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

        # QUICK TEST
if __name__ == "__main__":
    extractor = IOCExtractor()
    print("==================================================")
    print(f'Quick Test')
    print("==================================================")
    print(extractor.extract('Attack from 198.51.100.17, hash d41d8cd98f00b204e9800998ecf8427e'))
    threat_iocs = load_misp(MISP_FEED) | load_stix(STIX_FEED)
    print(len(threat_iocs))
    print("==================================================")
    # Output is 5###


########## STEP 3 ############
import re
from collections import defaultdict
from datetime import datetime

def check_apache_bruteforce(logfile, alerts):
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
        # Wrap the file read in try/except FileNotFoundError
        with open(logfile) as f:
            for line in f:
                # Parse each line using the named-group regex
                m = pattern.match(line)
                if not m:
                    continue    # skip lines that don't match format

                # Collect (timestamp, ip) ONLY where status == '401'
                if m.group('status') == '401':
                    ip = m.group('ip')
                    ts_str = m.group('timestamp')

                    # parse timestamp
                    ts = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")

                    events[ip].append(ts)

    except FileNotFoundError:
        return

    # sliding-window detection (For each IP, sort the list, then scan windows of BRUTE_THRESHOLD events)
    for ip, timestamps in events.items():
        timestamps.sort()               # sort timestamps for sliding window

        # Sliding-window algorithm from Section 2.4
        for i in range(len(timestamps) - BRUTE_THRESHOLD + 1):
            start = timestamps[i]
            end = timestamps[i + BRUTE_THRESHOLD - 1]

            # Check if the window fits inside BRUTE_WINDOW seconds
            delta = (end - start).total_seconds()

            if delta <= BRUTE_WINDOW:
                # If condition met, append alert
                alerts.append({
                    'source': 'apache',
                    'type': 'BRUTE_FORCE',
                    'detail': f'{ip} triggered brute force'
                })

                # Break after first matching window per IP
                break


########## STEP 4 ############
from collections import defaultdict
import re

# Section 3.3 code exactly
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3}) +(?P<day>\d+) (?P<time>[\d:]+) '
    r'(?P<host>\S+) (?P<proc>\S+?)(\[(?P<pid>\d+)\])?: '
    r'(?P<msg>.+)$'
)

SSH_FAIL   = re.compile(r'Failed password.*from (?P<ip>[\d.]+)')
SSH_ACCEPT = re.compile(r'Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+)')
NEW_USER   = re.compile(r'new user: name=(?P<name>\w+), UID=(?P<uid>\d+)')

def check_syslog_bruteforce(logfile, alerts):
    # Count failures per IP
    fail_counts = defaultdict(int)

    try:
        with open(logfile) as f:
            for line in f:
                # parse syslog line with SYSLOG_RE
                m = SYSLOG_RE.match(line)
                if not m:
                    continue  # skip invalid lines

                entry = m.groupdict()   # 'entry' contains ['month','day','time','host','proc','pid','msg']
                msg = entry['msg']

                # check SSH_FAIL on entry['msg']
                ssh_fail = SSH_FAIL.search(msg)
                if ssh_fail:
                    ip = ssh_fail.group('ip')
                    fail_counts[ip] += 1

                # bonus NEW_USER UID=0 detection
                new_user = NEW_USER.search(msg)
                if new_user and new_user.group('uid') == '0':
                    alerts.append({
                        'source': 'syslog',
                        'type': 'NEW_ROOT_USER',
                        'detail': f"{new_user.group('name')} created with UID 0"
                    })

    except FileNotFoundError:
        return

    # if any IP has failures >= threshold, append alert
    for ip, count in fail_counts.items():
        if count >= BRUTE_THRESHOLD:
            alerts.append({
                'source': 'syslog',
                'type': 'SSH_BRUTE_FORCE',
                'detail': f'{ip} — {count} SSH failures'
            })


########## STEP 5 ############
import json

def check_suricata(logfile, alerts):
    """
    Parse Suricata eve.json log and collect only high-severity alerts (severity == 1).
    """
    try:
        with open(logfile) as f:
            for line in f:
                try:
                    # Parse each line as JSON
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # Skip invalid JSON lines
                    continue

                # Keep only events where event_type == 'alert' AND alert.severity == 1
                if event.get('event_type') != 'alert':
                    continue

                alert = event.get('alert', {})
                if alert.get('severity') != 1:
                    continue

                # Extract required details
                src_ip = event.get('src_ip', 'unknown')
                dest_ip = event.get('dest_ip', 'unknown')
                dest_port = event.get('dest_port', 'unknown')
                signature = alert.get('signature', 'unknown')

                # Append alert in the required format
                alerts.append({
                    'source': 'suricata',
                    'type': 'HIGH_SEV_ALERT',
                    'detail': f'{src_ip} -> {dest_ip}:{dest_port} | {signature}'
                })

    except FileNotFoundError:
        # Do not crash if file is missing
        return


########## STEP 6 ############
from pathlib import Path

def check_ioc_matches(logfile, threat_iocs, source, alerts):
    """
    Check a log file for any IOCs that match the threat feed.
    """
    # Read the entire log file as a single string
    try:
        text = Path(logfile).read_text()
    except FileNotFoundError:
        return  # do not crash if file missing

    # Run extractor.extract(text) to get all IOCs found in the file
    extractor = IOCExtractor()  # assume IOCExtractor defined as in Step 1
    extracted = extractor.extract(text)

    # For each extracted IOC type and value
    for ioc_type, values in extracted.items():
        for val in values:
            # If value matches threat feed
            if val.lower() in threat_iocs:
                # Append alert in required format
                alerts.append({
                    'source': source,
                    'type': 'IOC_MATCH',
                    'detail': f'{ioc_type}={val} matched threat feed'
                })


########## STEP 7: MAIN FUNCTION ###########
def main():
    # Instantiate IOCExtractor
    extractor = IOCExtractor()

    # Load threat feeds
    threat_iocs = load_misp(MISP_FEED) | load_stix(STIX_FEED)
    print(f'Total threat IOCs loaded: {len(threat_iocs)}')

    # Shared alerts list
    alerts = []

    # Call all six check functions in order
    check_apache_bruteforce(APACHE_LOG, alerts)
    check_syslog_bruteforce(SYSLOG_LOG, alerts)
    check_suricata(SURICATA_LOG, alerts)
    check_ioc_matches(APACHE_LOG, threat_iocs, 'apache', alerts)
    check_ioc_matches(SYSLOG_LOG, threat_iocs, 'syslog', alerts)
    check_ioc_matches(SURICATA_LOG, threat_iocs, 'suricata', alerts)

    # Print alert report
    if not alerts:
        print('[OK] No alerts triggered.')
    else:
        print("==================================================")
        print(f'[ALERTS] {len(alerts)} triggered:')
        print("==================================================")
        for i, alert in enumerate(alerts, 1):
            print(f"{i}. Source: {alert['source']}, Type: {alert['type']}, Detail: {alert['detail']}")


# Guarded entry point
if __name__ == '__main__':
    main()
