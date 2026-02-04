from datetime import timedelta

# ================= HEAVY ACTIVITY =================
def detect_heavy_activity(ip_counter, base_threshold=None):
    """
    Classify IPs based on total accumulated attempts.
    Every IP is included. Severity depends on volume.
    """

    data = []

    for ip, count in ip_counter.items():
        # Risk score = cumulative behavior
        risk_score = count * 10

        if risk_score >= 100:
            severity = "HIGH"
        elif risk_score >= 50:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        data.append({
            "ip": str(ip),
            "attempts": int(count),
            "risk_score": risk_score,
            "severity": severity
        })

    return {
        "detector": "Heavy Activity",
        "total_detected": len(data),
        "data": data
    }


# ================= BURST ACTIVITY =================
def detect_bursts(ip_timestamps, window_minutes=2, threshold=5):
    """
    Detect fast repeated attacks in a short time window.
    Only flags IPs that burst.
    """

    data = []
    window = timedelta(minutes=window_minutes)

    for ip, timestamps in ip_timestamps.items():
        if len(timestamps) < threshold:
            continue

        timestamps.sort()

        for i in range(len(timestamps)):
            count = 1
            for j in range(i + 1, len(timestamps)):
                if timestamps[j] - timestamps[i] <= window:
                    count += 1
                else:
                    break

            if count >= threshold:
                data.append({
                    "ip": str(ip),
                    "event_count": count,
                    "window_minutes": window_minutes,
                    "start_time": timestamps[i].strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH"
                })
                break

    return {
        "detector": "Burst Activity",
        "total_detected": len(data),
        "data": data
    }


# ================= MULTI ATTACK =================
def detect_multi_attack(ip_attack_types):
    """
    Detect IPs performing multiple attack types.
    """

    data = []

    for ip, attack_types in ip_attack_types.items():
        attack_count = len(attack_types)

        if attack_count == 0:
            continue

        if attack_count >= 3:
            severity = "HIGH"
        elif attack_count == 2:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        data.append({
            "ip": str(ip),
            "attack_types": sorted(list(attack_types)),
            "attack_count": attack_count,
            "severity": severity
        })

    return {
        "detector": "Multi Attack",
        "total_detected": len(data),
        "data": data
    }
