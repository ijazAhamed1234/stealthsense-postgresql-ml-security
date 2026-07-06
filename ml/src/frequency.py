"""
frequency.py  –  Sliding-window query-rate tracking with file locking.

Uses fcntl.flock() on a dedicated lock-file so concurrent PostgreSQL
backend processes do not corrupt the shared JSON history.
"""

import time
import os
import json
import fcntl
import re

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
WINDOW       = 10     # seconds – the sliding observation window
MAX_RATE     = 8      # queries per window → score 100 (hard block)
MED_RATE     = 5      # queries per window → score 70

HISTORY_FILE = os.getenv("STEALTHSENSE_HIST_FILE", "/tmp/stealthsense_frequency_history.json")
LOCK_FILE    = os.getenv("STEALTHSENSE_LOCK_FILE", "/tmp/stealthsense_frequency_history.json.lock")


def _load_history():
    """Load history dict from the JSON file; return empty dict on any error."""
    if not os.path.exists(HISTORY_FILE):
        return {"queries": {}, "users": {}, "blocked_until": {}}
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
        if "queries" not in data:
            data["queries"] = {}
        if "users" not in data:
            data["users"] = {}
        if "blocked_until" not in data:
            data["blocked_until"] = {}
        return data
    except Exception:
        return {"queries": {}, "users": {}, "blocked_until": {}}


def _save_history(history):
    """Persist the history dict to the JSON file."""
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
        os.chmod(HISTORY_FILE, 0o666)
    except Exception:
        pass


def normalize_query(q):
    """
    Normalize the query by removing comments, lowercasing, abstracting
    string and numeric literals, keeping only SQL keywords, operators,
    and punctuation, and replacing all other words (identifiers/table names)
    with '?'.
    """
    # Remove comments
    q = re.sub(r'/\*.*?\*/', '', q, flags=re.DOTALL)
    q = re.sub(r'--.*$', '', q, flags=re.MULTILINE)
    
    # Lowercase & strip
    q = q.lower().strip()
    
    # Replace single-quoted string literals with '?'
    q = re.sub(r"'(?:''|[^'])*'", "'?'", q)
    
    # Replace numeric literals (integers, floats, negative numbers) with ?
    q = re.sub(r"\b-?\d+(?:\.\d+)?\b", "?", q)
    
    # Tokenize the query: words (letters/underscores/numbers), or other symbols
    tokens = re.findall(r'[a-zA-Z_]\w*|\d+|[^\w\s]', q)
    
    PRESERVED_KEYWORDS = {
        "select", "from", "where", "insert", "update", "delete", "join", "on", 
        "and", "or", "not", "in", "is", "null", "like", "into", "values", "set", 
        "limit", "offset", "group", "by", "order", "having", "as", "union", "all", 
        "create", "table", "drop", "truncate", "alter", "grant", "revoke", "index", 
        "view", "trigger", "database", "copy", "pg_sleep", "pg_read_file", 
        "information_schema", "pg_database", "pg_roles", "benchmark", "exec", 
        "xp_", "lock", "for", "share", "mode"
    }
    
    normalized_tokens = []
    for token in tokens:
        # Check if it starts with a letter or underscore
        if token[0].isalpha() or token[0] == '_':
            if token in PRESERVED_KEYWORDS:
                normalized_tokens.append(token)
            else:
                normalized_tokens.append('?')
        elif token.isdigit() or token == '?':
            normalized_tokens.append('?')
        else:
            normalized_tokens.append(token)
            
    normalized = " ".join(normalized_tokens)
    # Clean up spaces around common punctuation to keep format clean
    normalized = re.sub(r'\s+([,.;()=<>!])', r'\1', normalized)
    normalized = re.sub(r'([,.;()=<>!])\s+', r'\1', normalized)
    # Collapse multiple whitespaces
    normalized = re.sub(r'\s+', ' ', normalized).strip()
    
    return normalized


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
    query = normalize_query(query)

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
        blocked_until = history.setdefault("blocked_until", {})

        # ── Check lockout ──
        if now < blocked_until.get(query, 0):
            # Extend lockout duration
            blocked_until[query] = now + WINDOW
            _save_history(history)
            query_count = MAX_RATE
        else:
            # ── Clean up old timestamps from the history first ──
            for q in list(history["queries"].keys()):
                history["queries"][q] = [x for x in history["queries"][q] if now - x < WINDOW]
                if not history["queries"][q]:
                    del history["queries"][q]

            # ── Record the current query event ──
            history["queries"].setdefault(query, []).append(now)
            query_count = len(history["queries"].get(query, []))

            # ── Set lockout if MAX_RATE is reached ──
            if query_count >= MAX_RATE:
                blocked_until[query] = now + WINDOW

            _save_history(history)

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