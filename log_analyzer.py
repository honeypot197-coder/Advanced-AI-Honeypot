import time
import json
import os
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from collections import Counter

from analyzer.parser import parse_logs, init_runtime_structures
from analyzer.detectors import detect_heavy_activity, detect_multi_attack, detect_bursts
from analyzer.report import build_report, print_report
from analyzer.state import load_state, save_state, reset_state_for_new_session
from port_analyzer import analyze_port_scan

# ================= CONFIG & CONSTANTS =================
CONFIG_FILE = "config.json"
REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "attack_report.json")
SYSTEM_LOG_FILE = os.path.join(REPORT_DIR, "system_logs.txt")
LOG_DIR = "logs"
BLACKLIST_FILE = "blacklist.txt"
REPORT_INTERVAL = 5 

# إعدادات الإيميل (Email Credentials)
EMAIL_SENDER = "honeypot197@gmail.com"
EMAIL_PASSWORD = "bknv zvkb ingy owav" 
EMAIL_RECEIVER = "honeypot197@gmail.com"

# متغير لمتابعة آخر حالة تم إرسال إيميل عنها لمنع التكرار المزعج
last_alert_sent = None

def load_system_config():
    """تحميل الإعدادات من ملف config.json مع قيم افتراضية"""
    default_config = {
        "suspicious_ip_threshold": 3,
        "burst_window_minutes": 1,
        "burst_threshold": 10,
        "auto_block_threshold": 15
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                user_config = json.load(f)
                return {**default_config, **user_config}
        except:
            return default_config
    return default_config

ATTACK_LOGS = {
    "brute.log": "Brute Force",
    "port.log": "Port Scan",
    "sqli.log": "SQL Injection",
    "credential.log": "Credential Stuffing"
}

ATTACK_SEVERITY = {
    "Brute Force": "MEDIUM",
    "Port Scan": "LOW",
    "SQL Injection": "HIGH",
    "Credential Stuffing": "HIGH"
}

# ================= HELPER FUNCTIONS =================

def log_action(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    with open(SYSTEM_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")

def send_email_alert(status, total_hits, top_ip):
    """إرسال تنبيه بريدي احترافي"""
    subject = f"🚨 {status} Security Alert - AI Honeypot"
    body = f"""
    SECURITY ALERT REPORT
    ---------------------
    System Status: {status}
    Total Detected Attacks: {total_hits}
    Main Attacker IP: {top_ip}
    Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    Action Taken: System is monitoring and auto-blocking based on rules.
    Check the Dashboard (Action Logs) for more details.
    """
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        log_action(f"📧 EMAIL SENT: Alert for status {status} sent to admin.")
    except Exception as e:
        log_action(f"❌ EMAIL ERROR: Could not send alert ({str(e)})")

# ================= MAIN RUNNER =================

def run_live_analyzer():
    global last_alert_sent
    print("[+] Honeypot Analyzer running (LIVE MODE - Fully Integrated)")
    os.makedirs(REPORT_DIR, exist_ok=True)

    # تصفير سجل العمليات للجلسة الجديدة
    with open(SYSTEM_LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"--- Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    log_action("🛡️ System Initialized. Defense Engine Active.")

    # 1. تصفير الجلسة وتنظيف الملفات القديمة
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    state = {} 
    reset_state_for_new_session(state, session_id)
    save_state(state)
    
    print("[*] Cleaning old log files...")
    for log_file in ATTACK_LOGS.keys():
        log_path = os.path.join(LOG_DIR, log_file)
        if os.path.exists(log_path):
            with open(log_path, "w"): pass
    
    if os.path.exists(REPORT_FILE):
        try: os.remove(REPORT_FILE)
        except: pass
            
    runtime = init_runtime_structures()

    while True:
        current_cfg = load_system_config()
        
        # -------- Parse logs LIVE --------
        parse_logs(log_dir=LOG_DIR, attack_logs=ATTACK_LOGS, runtime=runtime, session_id=session_id)

        ip_counter = runtime.get("ip_counter", {})
        attack_counter = runtime.get("attack_counter", {})
        hourly_activity = runtime.get("hourly_activity", {})
        ip_timestamps = runtime.get("ip_timestamps", {})
        ip_attack_types = runtime.get("ip_attack_types", {})

        # 1. منطق الحظر التلقائي (Auto-Block)
        auto_block_limit = current_cfg.get("auto_block_threshold", 15)
        for ip, count in ip_counter.items():
            if count >= auto_block_limit:
                already_blocked = False
                if os.path.exists(BLACKLIST_FILE):
                    with open(BLACKLIST_FILE, "r") as f:
                        if ip in f.read(): already_blocked = True
                
                if not already_blocked:
                    with open(BLACKLIST_FILE, "a") as f:
                        f.write(f"AUTO-BLOCKED: {ip} | {datetime.now()} | Hits: {count}\n")
                    log_action(f"⚡ AUTO-BLOCK: IP {ip} was blocked (Attempts: {count})")

        # 2. منطق الحساسية والـ Detectors
        suspicious_limit = current_cfg.get("suspicious_ip_threshold", 3)
        burst_win = current_cfg.get("burst_window_minutes", 1)
        burst_limit = current_cfg.get("burst_threshold", 10)

        heavy_ips = detect_heavy_activity(ip_counter, suspicious_limit)
        multi_ips = detect_multi_attack(ip_attack_types)
        burst_ips = detect_bursts(ip_timestamps, burst_win, burst_limit)
        port_scan = analyze_port_scan(os.path.join(LOG_DIR, "port.log"), threshold=10)

        # 3. حساب مستوى الخطورة وتحديد الحالة العامة
        total_hits = sum(attack_counter.values())
        high_count = sum(count for atk, count in attack_counter.items() if ATTACK_SEVERITY.get(atk) == "HIGH")
        med_count = sum(count for atk, count in attack_counter.items() if ATTACK_SEVERITY.get(atk) == "MEDIUM")
        top_ip = max(ip_counter, key=ip_counter.get) if ip_counter else "None"

        if total_hits == 0: overall_status = "LOW"
        elif high_count > (total_hits * 0.1) or len(multi_ips.get("data", [])) > 2: overall_status = "CRITICAL"
        elif high_count > 0 or med_count > 10: overall_status = "HIGH"
        elif total_hits > 20: overall_status = "MEDIUM"
        else: overall_status = "LOW"

        # --- تفعيل نظام التنبيه البريدي ---
        if overall_status in ["HIGH", "CRITICAL"] and overall_status != last_alert_sent:
            send_email_alert(overall_status, total_hits, top_ip)
            last_alert_sent = overall_status
        elif overall_status == "LOW":
            last_alert_sent = None # إعادة تصفير التنبيه إذا هدأ النظام

        # 4. التقرير النهائي للواجهة
        attack_types_list = [{"attack_type": atk, "count": int(cnt), "severity": ATTACK_SEVERITY.get(atk, "MEDIUM")} for atk, cnt in attack_counter.items()]
        
        final_report = {
            "overall_system_status": overall_status,
            "summary": {
                "total_attacks": total_hits,
                "most_frequent_attack": max(attack_counter, key=attack_counter.get) if attack_counter else "None",
                "top_attacker": {"ip": top_ip, "count": max(ip_counter.values()) if ip_counter else 0},
                "hourly_stats": dict(hourly_activity),
                "attacks_by_type_list": attack_types_list
            },
            "live_table": [
                {"ip": ip, "attempts": cnt, "severity": "CRITICAL" if cnt >= auto_block_limit else "HIGH" if cnt > 5 else "LOW"}
                for ip, cnt in ip_counter.items()
            ],
            "detections_detailed": {
                "heavy_activity": heavy_ips, "multi_attack": multi_ips, "burst_activity": burst_ips,
                "port_scan_activity": {"total_detected": len(port_scan), "data": [{"ip": k, "ports": v} for k, v in port_scan.items()]}
            }
        }

        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=4)

        print(f"\r[+] Status: {overall_status} | Attacks: {total_hits} | Email Engine: Active ", end="")
        time.sleep(REPORT_INTERVAL)

if __name__ == "__main__":
    run_live_analyzer()