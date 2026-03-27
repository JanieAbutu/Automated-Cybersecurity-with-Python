# run_simulation.py
import os
import threading
import time
from datetime import datetime
from rce_server import RCEServer
from rce_client import RCEClient
from session_logger import SessionLogger
from detection_engine import DetectionEngine
from dashboard import Dashboard

# ---------------------------
# Configuration
# ---------------------------
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
TOKEN = 'secret-token'

SESSIONS = [
    ['whoami', 'ls', 'pwd'],
    ['net user', 'ipconfig', 'dir'],
    ['echo Test session 3', 'uname -a']
]

LOGS_DIR = 'session_logs'
REPORTS_DIR = 'detection_reports'
DASHBOARD_DIR = 'dashboards'

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(DASHBOARD_DIR, exist_ok=True)

# ---------------------------
# Helper Functions
# ---------------------------

def run_session(session_id, commands):
    """
    Run a single controlled RCE session.
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(LOGS_DIR, f'session_{session_id}_{timestamp}.json')
    report_file = os.path.join(REPORTS_DIR, f'detection_{session_id}_{timestamp}.json')
    dashboard_file = os.path.join(DASHBOARD_DIR, f'dashboard_{session_id}_{timestamp}.html')

    # Initialize logger
    logger = SessionLogger(log_file)

    # Start server in a thread
    server = RCEServer(host=SERVER_HOST, port=SERVER_PORT, token=TOKEN, logger=logger)

    def server_thread():
        server.start()

    t_server = threading.Thread(target=server_thread, daemon=True)
    t_server.start()
    time.sleep(1)  # wait for server to start

    # Start client
    client = RCEClient(server_host=SERVER_HOST, server_port=SERVER_PORT, token=TOKEN, logger=logger)
    client.connect()
    if not client.authenticate():
        print("Client authentication failed.")
        return

    # Simulate sending commands
    for cmd in commands:
        # Server sends command to client
        print(f"[Session {session_id}] Sending command: {cmd}")
        server.handle_client(client.conn)  # will send command and receive output
        time.sleep(0.5)

    # End session
    client.conn.send(b'exit')
    time.sleep(1)
    logger.log_event('Session', 'completed', f'Session {session_id} completed')

    # Run detection engine
    detector = DetectionEngine(log_file)
    detector.load_logs()
    detector.analyze()
    detector.generate_report(report_file)

    # Generate dashboard
    dash = Dashboard(log_file, report_file)
    dash.load_data()
    dash.generate_timeline(dashboard_file)

    print(f"[Session {session_id}] Completed. Logs, detection report, and dashboard generated.")

# ---------------------------
# Main: Run All Sessions
# ---------------------------

for i, cmd_set in enumerate(SESSIONS, start=1):
    run_session(i, cmd_set)
    print(f"Session {i} finished.\n\n")