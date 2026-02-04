import os
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict

# ================= REGEX =================
LOG_REGEX = re.compile(
    r"\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?(from )?(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# ================= PARSER =================
def parse_logs(log_dir, attack_logs, runtime, session_id):
    """
    محلل السجلات الحي:
    1. يصفر البيانات إذا تغير الـ Session.
    2. يقرأ فقط الأسطر الجديدة.
    3. يحول البيانات لشكل يقبله الـ Dashboard.
    """
    
    # تأكد من استيراد الدوال هنا لتجنب Circular Import
    from analyzer.state import load_state, save_state, get_last_position, update_position, reset_state_for_new_session

    state = load_state()

    # 🔥 تصفير كامل عند بداية كل جلسة جديدة لضمان عدم حفظ القديم
    if state.get("session_id") != session_id:
        # مسح ملف الحالة القديم نهائياً
        reset_state_for_new_session(state, session_id)
        save_state(state)

        # تفريغ الذاكرة المؤقتة
        runtime["attack_counter"].clear()
        runtime["ip_counter"].clear()
        runtime["hourly_activity"].clear()
        runtime["ip_timestamps"].clear()
        runtime["ip_attack_types"].clear()

    for filename, attack_type in attack_logs.items():
        file_path = os.path.join(log_dir, filename)
        if not os.path.exists(file_path):
            continue

        # الحصول على آخر موضع قراءة (Pointer)
        last_position = get_last_position(state, filename)

        with open(file_path, "r", encoding="utf-8") as f:
            f.seek(last_position)

            for line in f:
                match = LOG_REGEX.search(line)
                if not match: continue

                ip = match.group("ip")
                time_str = match.group("time")

                # تحديث العدادات بشكل تراكمي في الذاكرة
                runtime["attack_counter"][attack_type] += 1
                runtime["ip_counter"][ip] += 1
                
                # إضافة نوع الهجوم (ستتحول لاحقاً لـ List في التقرير)
                runtime["ip_attack_types"][ip].add(attack_type)

                try:
                    timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                    hour = timestamp.strftime("%H")
                    runtime["hourly_activity"][hour] += 1
                    runtime["ip_timestamps"][ip].append(timestamp)

                    # نافذة زمنية للتحليل (آخر 30 دقيقة مثلاً)
                    cutoff = datetime.now() - timedelta(minutes=30)
                    runtime["ip_timestamps"][ip] = [t for t in runtime["ip_timestamps"][ip] if t >= cutoff]
                except ValueError:
                    pass

            # تحديث الموضع في الملف لكي لا يقرأ السطر نفسه مرة أخرى
            update_position(state, filename, f.tell())

    save_state(state)

def init_runtime_structures():
    return {
        "attack_counter": defaultdict(int),
        "ip_counter": defaultdict(int),
        "hourly_activity": defaultdict(int),
        "ip_timestamps": defaultdict(list),
        "ip_attack_types": defaultdict(set)
    }