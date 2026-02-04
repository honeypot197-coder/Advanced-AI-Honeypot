from datetime import datetime
from collections import Counter

# ======================================================
# JSON REPORT BUILDER
# ======================================================
def build_report(
    attack_counter,
    ip_counter,
    hourly_activity,
    detections,
    attack_severity,
    honeypot_id="honeypot-01"
):
    """
    Build structured attack report (JSON-ready) compatible with our detectors
    """

    total_attacks = sum(attack_counter.values())

    # ===== Heavy Activity =====
    heavy_list = [
        {
            "ip": item["ip"],
            "attempts": item.get("request_count", attack_counter.get(item["ip"], 0)),
            "severity": item.get("severity", "MEDIUM")
        }
        for item in detections.get("heavy_activity", {}).get("data", [])
    ]

    # ===== Multi Attack =====
    multi_list = [
        {
            "ip": item["ip"],
            "attack_types": item.get("attack_types", []),
            "severity": item.get("severity", "MEDIUM")
        }
        for item in detections.get("multi_attack", {}).get("data", [])
    ]

    # ===== Burst Activity =====
    burst_list = [
        {
            "ip": item["ip"],
            "count": item.get("event_count", 0),
            "window_minutes": item.get("window_minutes", 0),
            "start_time": item.get("start_time", "")
        }
        for item in detections.get("burst_activity", {}).get("data", [])
    ]

    heavy_count = len(heavy_list)
    multi_count = len(multi_list)
    burst_count = len(burst_list)

    # ===== Risk calculation =====
    risk_level = "LOW"
    risk_reason = "Normal activity"
    if heavy_count or multi_count or burst_count:
        risk_level = "MEDIUM"
        risk_reason = "Suspicious IP activity detected"
    if heavy_count >= 3 or multi_count >= 2 or burst_count >= 2:
        risk_level = "HIGH"
        risk_reason = "High volume of coordinated attacks"

    # ===== Attacks by type =====
    attacks_by_type = {
        attack: {
            "count": attack_counter.get(attack, 0),
            "severity": attack_severity.get(attack, "LOW")
        }
        for attack in attack_severity
    }

    # ===== Hourly activity =====
    attacks_per_hour = {
        f"{int(hour):02d}": count
        for hour, count in sorted(hourly_activity.items())
    }

    # ===== Top attackers =====
    ip_counter = Counter(ip_counter)
    top_attackers = [
        {
            "ip": ip,
            "attempts": count,
            "risk": (
                "HIGH" if count >= 20
                else "MEDIUM" if count >= 10
                else "LOW"
            )
        }
        for ip, count in ip_counter.most_common(5)
    ]

    return {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "honeypot_id": honeypot_id,
            "analysis_version": "1.0",
            "mode": "LIVE"
        },
        "summary": {
            "risk_level": risk_level,
            "risk_score": _risk_score(risk_level),
            "reason": risk_reason
        },
        "metrics": {
            "total_attacks": total_attacks,
            "attacks_by_type": attacks_by_type,
            "attacks_per_hour": attacks_per_hour
        },
        "detections": {
            "heavy_activity": {
                "total_detected": heavy_count,
                "data": heavy_list
            },
            "multi_attack": {
                "total_detected": multi_count,
                "data": multi_list
            },
            "burst_activity": {
                "total_detected": burst_count,
                "data": burst_list
            }
        },
        "top_attackers": {
            "limit": 5,
            "items": top_attackers
        }
    }

# ======================================================
# CONSOLE REPORT
# ======================================================
def print_report(report):
    summary = report["summary"]
    metrics = report["metrics"]
    detections = report["detections"]

    print("\n" + "=" * 60)
    print("🛡️  HONEYPOT ATTACK REPORT (LIVE)")
    print("=" * 60)

    print(f"\n🔍 Risk Level : {summary['risk_level']}")
    print(f"📝 Reason     : {summary['reason']}")
    print(f"📊 Score      : {summary['risk_score']}")

    print("\n📊 Attack Statistics")
    print(f"- Total Attacks: {metrics['total_attacks']}")

    print("\n🧪 Attacks by Type:")
    for attack, data in metrics["attacks_by_type"].items():
        print(f"- {attack}: {data['count']} | Severity: {data['severity']}")

    print("\n⏰ Activity by Hour:")
    for hour, count in metrics["attacks_per_hour"].items():
        print(f"{hour}:00 → {count} attacks")

    print("\n🚨 Heavy Activity:")
    for e in detections["heavy_activity"]["data"]:
        print(f"- {e['ip']} | Attempts: {e['attempts']} | {e['severity']}")

    print("\n🔀 Multi Attack:")
    for e in detections["multi_attack"]["data"]:
        print(f"- {e['ip']} | {', '.join(e['attack_types'])} | {e['severity']}")

    print("\n⚡ Burst Activity:")
    for e in detections["burst_activity"]["data"]:
        print(
            f"- {e['ip']} | {e['count']} events "
            f"in {e['window_minutes']} min"
            f"{' | start: '+e['start_time'] if e.get('start_time') else ''}"
        )

    print("\n" + "=" * 60)

# ======================================================
# HELPERS
# ======================================================
def _risk_score(level):
    return {"LOW": 20, "MEDIUM": 40, "HIGH": 70}.get(level, 0)
