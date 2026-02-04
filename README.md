🛡️ Advanced AI Honeypot System
A powerful Python-based security suite for real-time log analysis, automated threat mitigation, and intelligent email alerting.

This project is designed to simulate a professional honeypot environment that not only detects attacks but actively defends the system

---

📌 Features
🔍 Intelligence & Detection
Multi-Vector Analysis: Specialized parsing for Brute Force, Port Scanning, SQL Injection, and Credential Stuffing attacks.

Risk Scoring Engine: Dynamically calculates system-wide security status (LOW to CRITICAL) based on attack density and severity.

⚡ Automated Defense & Active Response
Intelligent Auto-Blocker: Instantly mitigates threats by blacklisting IPs that exceed the auto_block_threshold defined in config.json.

Live Action Logs: A dedicated tab in the GUI that records every defensive maneuver (blocking, alerting, etc.) in real-time.

Manual Firewall Control: Right-click any "Top Attacker" to manually update blacklist.txt and block the IP instantly.

📧 Precision Email Alerting
SMTP Alert Engine: Securely transmits high-priority security reports to the administrator's email using Google App Passwords.

Smart Throttling: The system ensures you only receive one alert per risk level change, preventing inbox flooding.

📊 Interactive Dashboard (GUI)
Visual Analytics: Real-time Pie Charts (via Matplotlib) visualizing the distribution of attack types.

Smart Audio Cues: Threshold-based audible alerts that trigger when system risk transitions to a dangerous state.

## 📁 Project Structure



```
├── reports/
│   ├── attack_report.json   # Real-time data exchange (JSON Pipeline)
│   └── system_logs.txt      # Chronological log of automated actions
├── logs/
│   ├── brute.log, sqli.log  # Simulated raw honeypot logs
│   └── port.log             # Specialized port scanning logs
├── blacklist.txt            # Automatically generated/updated blocklist
├── config.json              # Centralized detection & threshold settings
├── log_analyzer.py          # Backend Engine (Analysis + Auto-Block + SMTP)
└── honeypot_gui.py          # Frontend Dashboard (Visuals + User Interaction)

▶️ Execution Workflow
Install Dependencies:

pip install matplotlib

Configure Environment (config.json):

Enter your sender email and your 16-character App Password to enable the alerting engine.

Launch the Analysis Engine:

python log_analyzer.py

(Starts live monitoring and defensive actions in the background).

Launch the Honeypot Dashboard:

python honeypot_gui.py

(Displays visual metrics and real-time Action Logs)

⚙️ Sensitivity Tuning (config.json)
Modify system behavior on-the-fly:

auto_block_threshold: The number of hits before an IP is automatically banned.

email_settings: Credentials for the SMTP alert system.