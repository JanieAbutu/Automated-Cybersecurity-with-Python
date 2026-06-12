# Secure Remote Administration Simulation (End-to-End C2 Simulation and Detection Pipeline)

## Project Overview

This project is a **controlled Command and Control (C2) simulation** built in Python to demonstrate how **Remote Command Execution (RCE)** works in a real-world scenario.

It helps **SOC analysts and blue teams** understand attacker behavior, logging visibility, and detection strategies.

---

## Objective

- Simulate **unauthorized remote access**
- Demonstrate **C2 communication**
- Execute **remote commands (RCE)**
- Generate **realistic logs**
- Build a **detection dashboard**
- Enable **easy replication for training**

---

## Key Concepts

### Command and Control (C2)
A communication channel used by an attacker to remotely control compromised systems.

### Remote Command Execution (RCE)
Allows execution of system commands on a remote machine and retrieval of output.

---

## Architecture

```
          ┌──────────────────────────┐
          │      Server (C2)         │
          │  - Sends commands        │
          │  - Receives output       │
          └──────────┬───────────────┘
                     │
                     │  Encrypted Channel (SSL)
                     │
          ┌──────────▼───────────────┐
          │      Client (Agent)      │
          │  - Executes commands     │
          │  - Returns output        │
          └──────────┬───────────────┘
                     │
                     │  Logs everything
                     ▼
          ┌──────────────────────────┐
          │   Logging Layer          │
          │ (session_logger.py)      │
          │  - Structured logs       │
          │  - JSON storage          │
          └──────────┬───────────────┘
                     │
                     ▼
          ┌──────────────────────────┐
          │   Detection Engine       │
          │ (detection_engine.py)    │
          │  - Behavioral analysis   │
          │  - Indicators            │
          └──────────┬───────────────┘
                     │
                     ▼
          ┌──────────────────────────┐
          │   Dashboard / Reporting  │
          │ (dashboard.py)           │
          │  - Timeline              │
          │  - Table / Visualization │
          └──────────────────────────┘
```
### Layered Architecture
**1. C2 Layer (Offensive Simulation)** 
- Server + Client
- Command execution
- Encrypted channel

**2. Telemetry Layer** 
- Full session logging
- Structured events (timestamp, bytes, type)

**3. Detection Layer** 
- Rule-based detection engine
- Identifies suspicious behavior
** 4. Visualization Layer** 
- HTML dashboard
- Analyst-friendly view

---

## Execution Flow
1. Server starts and listens on port 9999
2. Client connects to server
3. Authentication using pre-shared token
4. SSL encryption established
5. Server sends command
6. Client executes command (subprocess)
7. Client sends output back
8. Logs are generated
9. Detection engine analyzes logs
10. Dashboard generates HTML report

---

## Project Structure

C2C_SIMULATION/
│
├── dashboards/                # HTML dashboards
├── detection_reports/         # Detection outputs
├── session_logs/              # JSON logs
├── rce_env/                   # Virtual environment
│
├── rce_server.py              # Server
├── rce_client.py              # Client
├── session_logger.py          # Logging system
├── detection_engine.py        # Detection logic
├── dashboard.py               # Dashboard generator
├── run_simulation.py          # Main runner
│
├── server_cert.pem            # SSL Certificate
├── server_key.pem             # SSL Key
│
└── README.md

---

## Features

### Server (Handler)
- TCP server on `127.0.0.1:9999`
- Authenticates clients
- Sends commands

### Client (Agent)
- Connects to server
- Executes commands using `subprocess`
- Sends output back

### Encrypted Communication
- Uses Python `ssl`
- Prevents plaintext transmission

### Logging
Logs include:
- Connection attempts
- Authentication results
- Commands
- Outputs

Stored in:
```
session_logs/all_sessions.json
```

### Detection Engine
Detects:
- Suspicious commands
- Reconnaissance activity
- Execution anomalies

Output:
```
detection_reports/global_detection_report.json
```

### Detection Dashboard
HTML report showing:
- Timeline
- Commands
- Bytes transferred
- Indicators

```
dashboards/session_table.html
```

---

## Setup Instructions

### 1. Clone Repository
```bash
git clone https://github.com/JanieAbutu/c2c_simulation.git
cd c2c_simulation
```

### 2. Create Virtual Environment
```bash
python3 -m venv rce_env
source rce_env/bin/activate
```

### 3. Install Dependencies
```bash
pip install pandas cryptography
```

### 4. Run Simulation
```bash
python3 run_simulation.py
```

### 5. Select Mode
[1] Interactive
[2] Automated
---

## Outputs

| File | Description |
|------|------------|
| session_logs/all_sessions.json | Logs |
| detection_reports/global_detection_report.json | Detection results |
| dashboards/global_dashboard.html | Dashboard |

---

## Detection Insights

### Indicators of Compromise
- Repeated commands (whoami, ls, pwd)
- Unknown outbound connections
- Encrypted command channels
- Invalid OS commands:
  - net user
  - ipconfig

### Behavioral Patterns
- Rapid execution sequences
- Remote control behavior
- Output-based data exfiltration

---

## Mitigation

- Monitor outbound traffic
- Deploy EDR solutions
- Restrict command execution
- Network segmentation
- Behavioral detection rules

---

## Use Cases

- SOC training
- Detection engineering
- Red vs Blue simulations
- Cybersecurity education

---

## Disclaimer

For educational and defensive purposes only.  
Do not use without authorization.

---

## Summary

This project demonstrates:
- C2 communication
- RCE execution
- Logging and telemetry
- Detection techniques

Bridging:
**Offensive Simulation → Defensive Detection**

---
