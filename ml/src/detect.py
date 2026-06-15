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

    # ── Frequency score check FIRST ────────────────────────────────────────
    freq = query_frequency(clean_query, user)

    # ── Early Exit for Extreme Frequency Block ─────────────────────────────
    if freq >= 100:
        risk = 100
        verdict = "BLOCK"
    else:
        # Lazy load heavy dependencies only if we did not trigger an early block
        import pandas as pd
        import joblib

        # Load trained Random Forest model
        model = joblib.load(os.path.join(BASE_DIR, "../models/model.pkl"))

        # ── Feature extraction ─────────────────────────────────────────────
        features = extract_features(query)
        X        = pd.DataFrame([features])

        # ── ML score: probability the query is malicious (class 1), 0-100 ──
        ml_score = model.predict_proba(X)[0][1] * 100

        # ── Keyword risk score ─────────────────────────────────────────────
        keyword_score = min(features["keyword_hits"] * 10, 100)

        # ── IP trust score: 0 if whitelisted, 100 if unknown ──────────────
        ip_score = 0 if allowed(ip) else 100

        # ── Query complexity score ─────────────────────────────────────────
        complexity = min(features["multiple_queries"] * 20 + features["joins"] * 10, 100)

        # ── Composite risk score (weighted sum) ────────────────────────────
        risk = risk_score(ml_score, keyword_score, freq, ip_score, complexity)

        # ── Decision (calibrated thresholds) ──────────────────────────────
        if risk > 40:
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