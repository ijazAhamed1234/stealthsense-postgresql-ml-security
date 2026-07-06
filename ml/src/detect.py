import sys
import os
import traceback
import re

# ── Step 1: Resolve script location ───────────────────────────────────────
# os.path.abspath works even when Python is called via execv with a full path.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Step 2: Fix sys.path BEFORE any project imports ───────────────────────
# PostgreSQL calls this script via execv() with a stripped environment.
# sys.path will NOT contain ml/src, so feature_extractor etc. are invisible.
# We must insert BASE_DIR explicitly.
sys.path.insert(0, BASE_DIR)

# Also ensure the venv site-packages (pandas, scikit-learn, joblib) are found.
_venv_lib = os.path.join(BASE_DIR, "venv", "lib")
if os.path.isdir(_venv_lib):
    for _py_ver in os.listdir(_venv_lib):
        _sp = os.path.join(_venv_lib, _py_ver, "site-packages")
        if os.path.isdir(_sp) and _sp not in sys.path:
            sys.path.insert(1, _sp)

# ── Helper: safe append-open (never raises) ───────────────────────────────
def _safe_open(path):
    try:
        return open(path, "a")
    except Exception:
        return None

# ── Log paths ─────────────────────────────────────────────────────────────
DETECT_LOG = os.path.join(BASE_DIR, "../../logs/detections.log")
ERROR_LOG  = os.path.join(BASE_DIR, "../../logs/error.log")

# ── Main detection logic ───────────────────────────────────────────────────
try:
    from feature_extractor import extract_features
    from whitelist       import allowed
    from frequency       import query_frequency
    from risk_score      import risk_score

    # Arguments passed by the C extension via execv argv[]
    query = sys.argv[1] if len(sys.argv) > 1 else ""
    user  = sys.argv[2] if len(sys.argv) > 2 else "unknown"
    ip    = sys.argv[3] if len(sys.argv) > 3 else "unknown"

    # Strip comments from the query for frequency tracking
    clean_query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    clean_query = re.sub(r'--.*$', '', clean_query, flags=re.MULTILINE)
    clean_query = clean_query.strip()
    if clean_query.endswith(';'):
        clean_query = clean_query[:-1].strip()

    # ── First, extract features and check ML/keyword/structural maliciousness ──
    import pandas as pd
    import joblib

    # Load trained Random Forest model
    model = joblib.load(os.path.join(BASE_DIR, "../models/model.pkl"))

    # ── Feature extraction ─────────────────────────────────────────────
    query_for_extractor = query.strip()
    if query_for_extractor.endswith(';'):
        query_for_extractor = query_for_extractor[:-1].strip()

    features = extract_features(query_for_extractor)
    X        = pd.DataFrame([features])

    # ── ML score: probability the query is malicious (class 1), 0-100 ──
    ml_score = model.predict_proba(X)[0][1] * 100

    # ── Keyword risk score ─────────────────────────────────────────────
    keyword_score = min(features["keyword_hits"] * 10, 100)

    # ── IP trust score: 0 if whitelisted, 100 if unknown ──────────────
    ip_score = 0 if allowed(ip) else 100

    # ── Query complexity score ─────────────────────────────────────────
    complexity = min(features["multiple_queries"] * 20 + features["joins"] * 10, 100)

    # Identify if query is immediately malicious (e.g. drop table, SQLi, exfiltration)
    q_lower = query.lower().strip()
    if q_lower.endswith(';'):
        q_lower = q_lower[:-1].strip()

    is_session_control = False
    if ";" not in q_lower:
        for prefix in ["set ", "show ", "begin", "commit", "rollback", "explain ", "deallocate ", "discard "]:
            if q_lower.startswith(prefix) or q_lower == prefix.strip():
                is_session_control = True
                break

    is_malicious = False
    if is_session_control:
        ml_score = 0.0
        keyword_score = 0.0
        is_malicious = False
    else:
        if ml_score > 85:
            is_malicious = True
        elif "drop" in q_lower or "truncate" in q_lower or "grant" in q_lower or "revoke" in q_lower or "union" in q_lower:
            is_malicious = True
        elif "pg_sleep" in q_lower or "pg_read_file" in q_lower:
            is_malicious = True
        elif "or 1=1" in q_lower or "or '1'='1'" in q_lower or "or 1 = 1" in q_lower or "or '1' = '1'" in q_lower:
            is_malicious = True

    if is_malicious:
        # Malicious queries block immediately without calling query_frequency (no rate tracking)
        risk = max(risk_score(ml_score, keyword_score, 10, ip_score, complexity), 100.0)
        verdict = "BLOCK"
    else:
        # Benign queries check rate-limiting / query frequency
        freq = query_frequency(clean_query, user)
        risk = risk_score(ml_score, keyword_score, freq, ip_score, complexity)

        # Decision
        if freq >= 100 or risk > 40:
            verdict = "BLOCK"
        elif risk >= 25:
            verdict = "LOG"
        else:
            verdict = "ALLOW"

    # ── Write audit log entry (single sanitized line) ──────────────────────
    log_fh = _safe_open(DETECT_LOG)
    if log_fh:
        safe_q = query.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        log_fh.write(f"[{verdict}] risk={risk:.1f} user={user} ip={ip} query={safe_q}\n")
        log_fh.close()

    # ── Output verdict to C extension via stdout pipe ──────────────────────
    if verdict == "BLOCK":
        print(1)
    else:
        print(0)

except Exception:
    # Write full traceback to error.log, then fail-safe (allow query).
    # This ensures a broken model or import never takes down the database.
    err_fh = _safe_open(ERROR_LOG)
    if err_fh:
        err_fh.write("=== detect.py unhandled exception ===\n")
        err_fh.write(f"argv: {sys.argv}\n")
        err_fh.write(traceback.format_exc())
        err_fh.write("\n")
        err_fh.close()
    print(0)   # fail-safe: allow the query