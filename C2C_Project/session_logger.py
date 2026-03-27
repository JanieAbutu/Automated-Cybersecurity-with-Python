# session_logger.py
import json
import logging
from datetime import datetime

class SessionLogger:
    """
    Centralized logger for the RCE simulation.
    Captures all events with timestamps, bytes, status, and encrypted channel flag.
    """

    def __init__(self, session_id: str, log_level=logging.INFO):
        self.session_id = session_id
        self.logs = []
        logging.basicConfig(level=log_level,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def log_event(self, component: str, event_type: str, details: str = "",
                  bytes_transferred: int = 0, status: str = "ok",
                  channel: str = "plaintext"):
        """
        Logs a single structured event.
        """
        timestamp = datetime.utcnow().isoformat()
        event = {
            "timestamp": timestamp,
            "session_id": self.session_id,
            "component": component,       # e.g., Server, Client
            "event_type": event_type,     # e.g., connection_attempt, auth_success
            "details": details,           # e.g., command sent, output received
            "bytes": bytes_transferred,
            "status": status,             # ok, failure
            "channel": channel            # plaintext or encrypted
        }
        self.logs.append(event)
        logging.info(f"{component} | {event_type} | {details} | {bytes_transferred} bytes | {status} | {channel}")

    def save_session_logs(self, filepath: str):
        """
        Save all session logs to a JSON file.
        """
        with open(filepath, 'w') as f:
            json.dump(self.logs, f, indent=4)

    def load_session_logs(self, filepath: str):
        """
        Load logs from a JSON file for detection/dashboard use.
        """
        with open(filepath, 'r') as f:
            self.logs = json.load(f)
        return self.logs