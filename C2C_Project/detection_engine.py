# detection_engine.py
import json
from datetime import datetime

class DetectionEngine:
    """
    Analyzes session logs for indicators of unauthorized remote access.
    """
    def __init__(self, log_file):
        self.log_file = log_file
        self.logs = []
        self.indicators = []

    def load_logs(self):
        """
        Load JSON session logs.
        """
        with open(self.log_file, 'r') as f:
            self.logs = json.load(f)

    def analyze(self):
        """
        Analyze logs for RCE behavioral indicators.
        """
        for event in self.logs:
            # Example detection rules
            if event['event_type'] == 'auth_failure':
                self.indicators.append({
                    "timestamp": event['timestamp'],
                    "indicator": "Failed authentication attempt",
                    "details": event['details'],
                    "severity": "medium"
                })

            if event['event_type'] == 'command_received' and event['component'] == 'Client':
                cmd = event['details'].lower()
                if cmd in ['whoami', 'net user', 'ipconfig', 'ls', 'cat /etc/passwd']:
                    self.indicators.append({
                        "timestamp": event['timestamp'],
                        "indicator": f"Suspicious command executed: {cmd}",
                        "details": event['details'],
                        "severity": "high"
                    })

            if event['event_type'] == 'connection_attempt' and event['component'] == 'Client':
                self.indicators.append({
                    "timestamp": event['timestamp'],
                    "indicator": "Remote connection attempt",
                    "details": event['details'],
                    "severity": "low"
                })

        return self.indicators

    def generate_report(self, report_file='detection_report.json'):
        """
        Save detected indicators as a JSON report for dashboard use.
        """
        with open(report_file, 'w') as f:
            json.dump(self.indicators, f, indent=4)
        print(f"Detection report saved: {report_file}")