import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import time
from threading import Thread
from datetime import datetime

# استيراد مكتبات الرسم البياني
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# الإعدادات
REPORT_FILE = "reports/attack_report.json"
SYSTEM_LOG_FILE = "reports/system_logs.txt" # ملف سجل العمليات الجديد
UPDATE_INTERVAL = 2  
BLACKLIST_FILE = "blacklist.txt"

RISK_COLOR = {
    "LOW": "green",
    "MEDIUM": "orange",
    "HIGH": "red",
    "CRITICAL": "purple"
}

RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class LiveReportGUI:
    def __init__(self, root):
        self.root = root
        root.title("Advanced AI Honeypot Dashboard - Security Intelligence")
        root.geometry("1100x850")

        self.last_risk_status = "LOW"

        # ملصق مستوى الخطورة العام
        self.risk_label = tk.Label(root, text="SYSTEM STATUS: N/A", font=("Arial", 22, "bold"), fg="white", bg="grey")
        self.risk_label.pack(pady=15, fill=tk.X)

        # إعداد التبويبات
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(expand=1, fill="both")

        self.tab_attacks = ttk.Frame(self.tabs)
        self.tab_top_ips = ttk.Frame(self.tabs)
        self.tab_hourly = ttk.Frame(self.tabs)
        self.tab_detections = ttk.Frame(self.tabs)
        self.tab_charts = ttk.Frame(self.tabs)
        self.tab_system_logs = ttk.Frame(self.tabs) # التبويب السادس الجديد

        self.tabs.add(self.tab_attacks, text="Attacks by Type")
        self.tabs.add(self.tab_top_ips, text="Top Attackers (MAX Only)")
        self.tabs.add(self.tab_hourly, text="Hourly Activity")
        self.tabs.add(self.tab_detections, text="Detailed Detections")
        self.tabs.add(self.tab_charts, text="📊 Visual Analytics")
        self.tabs.add(self.tab_system_logs, text="📜 Action Logs") # إضافة التبويب للواجهة

        # بناء الجداول
        self.attack_table = self.make_table(self.tab_attacks, ("Attack Type", "Count", "Severity"))
        self.top_table = self.make_table(self.tab_top_ips, ("IP Address", "Total Attempts", "Risk Status"))
        self.hourly_table = self.make_table(self.tab_hourly, ("Hour", "Total Attacks"))
        self.detections_table = self.make_table(self.tab_detections, ("Detector Rule", "Attacker IP", "Detections Details", "Severity"))

        # --- إعداد شاشة سجل العمليات (Action Logs View) ---
        self.log_display = tk.Text(self.tab_system_logs, state='disabled', bg="#1e1e1e", fg="#00ff00", font=("Consolas", 11))
        self.log_display.pack(expand=True, fill='both', padx=10, pady=10)

        # إعداد مساحة الرسم البياني
        self.fig, self.ax = plt.subplots(figsize=(6, 5), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_charts)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # قائمة الحظر باليمين
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="🚫 Block IP & Add to Blacklist", command=self.block_ip_action)
        self.top_table.bind("<Button-3>", self.show_context_menu)

        Thread(target=self.update_loop, daemon=True).start()

    def make_table(self, parent, columns):
        table = ttk.Treeview(parent, columns=columns, show="headings")
        for col in columns:
            table.heading(col, text=col)
            table.column(col, anchor="center", width=200)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return table

    def show_context_menu(self, event):
        item = self.top_table.identify_row(event.y)
        if item:
            self.top_table.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def block_ip_action(self):
        selected = self.top_table.selection()
        if selected:
            ip = self.top_table.item(selected[0])['values'][0]
            with open(BLACKLIST_FILE, "a") as f:
                f.write(f"MANUAL-BLOCK: {ip} | Time: {datetime.now()}\n")
            
            # تسجيل العملية اليدوية في السجل ليراها المستخدم في التبويب الجديد
            self.write_to_system_log(f"🚫 User manually blocked IP: {ip}")
            messagebox.showwarning("Security Firewall", f"IP Address {ip} has been added to blacklist!")

    def write_to_system_log(self, message):
        """وظيفة مساعدة لتسجيل الأفعال في ملف السجل"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with open(SYSTEM_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    def play_sound_alert(self, current_risk):
        if RISK_ORDER.get(current_risk, 1) >= 3 and RISK_ORDER.get(self.last_risk_status, 1) < 3:
            try:
                import winsound
                winsound.Beep(1000, 500)
            except:
                print("\a")
        self.last_risk_status = current_risk

    def update_charts(self, attacks_list):
        if not attacks_list: 
            self.ax.clear()
            self.ax.text(0.5, 0.5, 'No Attack Data Yet', horizontalalignment='center', verticalalignment='center')
            self.canvas.draw()
            return
        
        labels = [item.get("attack_type") for item in attacks_list]
        sizes = [item.get("count") for item in attacks_list]
        self.ax.clear()
        colors = ['#ff9999','#66b3ff','#99ff99','#ffcc99', '#c2c2f0', '#ffb3e6']
        self.ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=colors)
        self.ax.set_title("Live Attack Distribution by Type")
        self.canvas.draw()

    def update_system_logs_display(self):
        """قراءة ملف السجلات وتحديث الشاشة في التبويب السادس"""
        if os.path.exists(SYSTEM_LOG_FILE):
            try:
                with open(SYSTEM_LOG_FILE, "r", encoding="utf-8") as f:
                    logs = f.readlines()
                self.log_display.config(state='normal')
                self.log_display.delete('1.0', tk.END)
                # عرض آخر 30 سطر لضمان سرعة الواجهة
                for line in logs[-30:]:
                    self.log_display.insert(tk.END, line)
                self.log_display.config(state='disabled')
                self.log_display.see(tk.END) # النزول التلقائي لآخر سطر
            except: pass

    def refresh_table(self, table):
        for row in table.get_children():
            table.delete(row)

    def update_loop(self):
        while True:
            self.root.after(0, self.load_report)
            time.sleep(UPDATE_INTERVAL)

    def load_report(self):
        if not os.path.exists(REPORT_FILE): return
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                report = json.load(f)
        except: return

        overall_risk = report.get("overall_system_status", "LOW")
        summary = report.get("summary", {})
        live_table = report.get("live_table", [])
        detections_detailed = report.get("detections_detailed", {})

        # تحديث الجداول والرسوم
        self.refresh_table(self.attack_table)
        attacks_list = summary.get("attacks_by_type_list", [])
        for item in attacks_list:
            self.attack_table.insert("", "end", values=(item.get("attack_type"), item.get("count"), item.get("severity")))
        
        self.update_charts(attacks_list)
        self.update_system_logs_display() # تحديث سجل العمليات

        self.refresh_table(self.top_table)
        if live_table:
            max_val = max(item.get("attempts", 0) for item in live_table)
            if max_val > 0:
                top_attackers = [ip for ip in live_table if ip.get("attempts", 0) == max_val]
                for item in top_attackers:
                    self.top_table.insert("", "end", values=(item.get("ip"), item.get("attempts"), item.get("severity")))

        self.refresh_table(self.hourly_table)
        hourly = summary.get("hourly_stats", {})
        for hour, count in sorted(hourly.items()):
            self.hourly_table.insert("", "end", values=(hour, count))

        self.refresh_table(self.detections_table)
        for rule, block in detections_detailed.items():
            detector_name = rule.replace("_", " ").title()
            for item in block.get("data", []):
                ip = item.get("ip", "N/A")
                sev = item.get("severity", "LOW")
                details = f"Rule: {detector_name}"
                if "attempts" in item: details = f"{item['attempts']} total hits"
                self.detections_table.insert("", "end", values=(detector_name, ip, details, sev))

        self.risk_label.config(text=f"SYSTEM SECURITY STATUS: {overall_risk}", bg=RISK_COLOR.get(overall_risk, "grey"))
        self.play_sound_alert(overall_risk)

if __name__ == "__main__":
    root = tk.Tk()
    app = LiveReportGUI(root)
    root.mainloop()