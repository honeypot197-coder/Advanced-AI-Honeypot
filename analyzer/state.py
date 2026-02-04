import json
import os
from datetime import datetime

STATE_FILE = "analyzer/state.json"

# ================= LOAD =================

def load_state():
    """
    Load analyzer state from file.
    Keeps track of last read position per log file + session.
    """
    if not os.path.exists(STATE_FILE):
        return {
            "session_id": None,
            "logs": {},
            "last_update": None
        }

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# ================= SAVE =================

def save_state(state):
    """
    Save analyzer state to file.
    """
    state["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=4)

# ================= POSITIONS =================

def get_last_position(state, log_name):
    """
    Get last read byte position for a specific log file.
    """
    return state.get("logs", {}).get(log_name, 0)


def update_position(state, log_name, position):
    """
    Update read position for a specific log file.
    """
    if "logs" not in state:
        state["logs"] = {}

    state["logs"][log_name] = position

# ================= SESSION CONTROL =================

def is_new_session(state, session_id):
    """
    Check if analyzer started a new session.
    """
    return state.get("session_id") != session_id


def reset_state_for_new_session(state, session_id):
    """
    Reset state when a new attack session starts.
    """
    state["session_id"] = session_id
    state["logs"] = {}  # ⬅️ نرجّع القراءة من بداية الملفات
    state["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
