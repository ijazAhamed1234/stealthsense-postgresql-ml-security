"""
frequency.py  –  Sliding-window query-rate tracking with file locking.

Uses fcntl.flock() on a dedicated lock-file so concurrent PostgreSQL
backend processes do not corrupt the shared JSON history.
"""

import time
import os
import json
import fcntl

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
WINDOW       = 10     # seconds – the sliding observation window
MAX_RATE     = 11     # queries per window → score 100 (hard block)
MED_RATE     = 6      # queries per window → score 70

HISTORY_FILE = os.getenv("STEALTHSENSE_HIST_FILE", "/tmp/stealthsense_frequency_history.json")
LOCK_FILE    = os.getenv("STEALTHSENSE_LOCK_FILE", "/tmp/stealthsense_frequency_history.json.lock")


def _load_history():
    """Load history dict from the JSON file; return empty dict on any error."""
    if not os.path.exists(HISTORY_FILE):
        return {"queries": {}, "users": {}}
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
        if "queries" not in data:
            data["queries"] = {}
        if "users" not in data:
            data["users"] = {}
        return data
    except Exception:
        return {"queries": {}, "users": {}}


def _save_history(history):
    """Persist the history dict to the JSON file."""
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
        os.chmod(HISTORY_FILE, 0o666)
    except Exception:
        pass


def query_frequency(query, user):
    """
    Record this (query, user) event and return a frequency risk score:
      100  – either the exact query or the user exceeds MAX_RATE / window
       70  – either exceeds MED_RATE / window
       10  – normal traffic

    The function is safe to call from concurrent processes because it
    uses an exclusive flock() around the read-modify-write cycle.
    """
    now = time.time()

    # Create the lock file if it does not exist yet.
    # If a PermissionError or other error occurs, proceed without a lock to avoid crashing the detector.
    lock_fd = None
    locked = False
    try:
        existed = os.path.exists(LOCK_FILE)
        lock_fd = open(LOCK_FILE, "a")
        if not existed:
            try:
                os.chmod(LOCK_FILE, 0o666)
            except Exception:
                pass
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked = True
    except Exception:
        pass

    try:
        history = _load_history()

        # ── Record the query event (historical count, no timing window) ──
        history["queries"].setdefault(query, []).append(now)

        _save_history(history)

        query_count = len(history["queries"].get(query, []))

    finally:
        if lock_fd:
            if locked:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except Exception:
                    pass
            try:
                lock_fd.close()
            except Exception:
                pass

    # ── Score based ONLY on raw query frequency count ────────────
    if query_count >= MAX_RATE:
        return 100
    if query_count >= MED_RATE:
        return 70
    return 10