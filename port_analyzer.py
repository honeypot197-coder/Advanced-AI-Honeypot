import re
from collections import defaultdict
from analyzer.state import (
    load_state,
    save_state,
    get_last_position,
    update_position
)

# Regex لالتقاط رقم البورت + عنوان IP
PORT_REGEX = re.compile(
    r"Port\s+(?P<port>\d+).*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def analyze_port_scan(log_file, threshold=10):
    """
    Analyze port scan attempts from log file.
    Returns dict: {ip: number_of_unique_ports}
    """

    state = load_state()
    attackers = defaultdict(set)

    last_pos = get_last_position(state, log_file)

    try:
        with open(log_file, "r", encoding="utf-8") as f:
            f.seek(last_pos)

            for line in f:
                match = PORT_REGEX.search(line)
                if not match:
                    continue

                ip = match.group("ip")
                port = int(match.group("port"))

                attackers[ip].add(port)

            # تحديث موضع القراءة
            update_position(state, log_file, f.tell())
            save_state(state)

    except FileNotFoundError:
        return {}

    # فلترة المهاجمين حسب threshold
    return {
        ip: len(ports)
        for ip, ports in attackers.items()
        if len(ports) >= threshold
    }
