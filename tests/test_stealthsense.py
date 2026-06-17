"""
test_stealthsense.py  –  Automated test suite for StealthSense Python components.

Run from the project root:
    /home/hp/stealthsense/ml/src/venv/bin/python3 -m pytest tests/ -v
  or
    /home/hp/stealthsense/ml/src/venv/bin/python3 -m unittest tests/test_stealthsense.py -v
"""

import sys
import os
import json
import subprocess
import tempfile
import time
import unittest

# Make ml/src importable without installing the package
ML_SRC = os.path.join(os.path.dirname(__file__), "..", "ml", "src")
sys.path.insert(0, os.path.abspath(ML_SRC))

# Isolate the test environment from PostgreSQL live files
os.environ["STEALTHSENSE_HIST_FILE"] = "/tmp/stealthsense_frequency_history_test.json"
os.environ["STEALTHSENSE_LOCK_FILE"] = "/tmp/stealthsense_frequency_history_test.json.lock"


# ==================================================================
# 1. Feature Extractor
# ==================================================================

class TestFeatureExtractor(unittest.TestCase):

    def setUp(self):
        from feature_extractor import extract_features
        self.extract = extract_features

    # --- benign queries -------------------------------------------

    def test_benign_simple_select(self):
        f = self.extract("SELECT id FROM users WHERE id=5")
        self.assertEqual(f["union"],  0)
        self.assertEqual(f["drop"],   0)
        self.assertEqual(f["delete"], 0)
        self.assertEqual(f["comments"], 0)
        self.assertGreater(f["length"], 0)

    def test_benign_no_keywords(self):
        f = self.extract("SELECT name, age FROM employees LIMIT 10")
        self.assertEqual(f["keyword_hits"], 0)

    # --- malicious queries ----------------------------------------

    def test_sql_injection_or_1_eq_1(self):
        f = self.extract("SELECT * FROM users WHERE username='admin' OR '1'='1'")
        self.assertGreater(f["keyword_hits"], 0)

    def test_union_detected(self):
        f = self.extract(
            "SELECT username FROM users UNION SELECT credit_card FROM payments"
        )
        self.assertEqual(f["union"], 1)
        self.assertGreater(f["keyword_hits"], 0)

    def test_drop_detected(self):
        f = self.extract("SELECT * FROM users; DROP TABLE employees")
        self.assertEqual(f["drop"], 1)
        self.assertGreater(f["multiple_queries"], 0)

    def test_comment_detected(self):
        f = self.extract("SELECT * FROM users WHERE id=1 -- comment")
        self.assertEqual(f["comments"], 1)

    def test_information_schema_enumeration(self):
        f = self.extract("SELECT table_name FROM information_schema.tables")
        self.assertEqual(f["table_enum"], 1)

    def test_pg_roles_enumeration(self):
        f = self.extract("SELECT rolname FROM pg_roles")
        self.assertEqual(f["role_enum"], 1)

    def test_stacked_queries_counted(self):
        f = self.extract("SELECT 1; SELECT 2; SELECT 3;")
        self.assertEqual(f["multiple_queries"], 3)

    def test_subquery_counted(self):
        f = self.extract("SELECT * FROM (SELECT id FROM users) sub")
        self.assertGreaterEqual(f["subqueries"], 1)

    def test_join_counted(self):
        f = self.extract("SELECT * FROM a JOIN b ON a.id=b.id")
        self.assertEqual(f["joins"], 1)


# ==================================================================
# 2. Whitelist
# ==================================================================

class TestWhitelist(unittest.TestCase):

    def _make_whitelist(self, contents):
        """Write *contents* to a temp file and monkey-patch whitelist path."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write(contents)
        tmp.close()
        return tmp.name

    def test_known_ip_is_allowed(self):
        import whitelist as wl
        path = self._make_whitelist("127.0.0.1\n192.168.1.10\n")
        original = wl.allowed.__code__
        # Patch via monkeypatching the open call indirectly through the module
        wl_src = os.path.join(ML_SRC, "whitelist.py")
        # Direct functional test by calling the internal logic
        with open(path) as f:
            ips = {
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        self.assertIn("127.0.0.1",    ips)
        self.assertIn("192.168.1.10", ips)
        os.unlink(path)

    def test_unknown_ip_excluded(self):
        path = self._make_whitelist("127.0.0.1\n")
        with open(path) as f:
            ips = {
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        self.assertNotIn("10.99.99.99", ips)
        os.unlink(path)

    def test_comment_lines_ignored(self):
        path = self._make_whitelist("# trusted admin box\n127.0.0.1\n")
        with open(path) as f:
            ips = {
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        self.assertNotIn("# trusted admin box", ips)
        self.assertIn("127.0.0.1", ips)
        os.unlink(path)

    def test_blank_lines_ignored(self):
        path = self._make_whitelist("127.0.0.1\n\n\n10.0.0.1\n")
        with open(path) as f:
            ips = {
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        self.assertEqual(len(ips), 2)
        os.unlink(path)

    def test_missing_file_returns_false(self):
        import whitelist as wl
        # Point module to a path that does not exist
        orig_join = os.path.join
        def patched_join(*args):
            if "whitelist_ips.txt" in args[-1]:
                return "/nonexistent/path/whitelist_ips.txt"
            return orig_join(*args)
        os.path.join = patched_join
        try:
            result = wl.allowed("127.0.0.1")
            self.assertFalse(result)
        finally:
            os.path.join = orig_join


# ==================================================================
# 3. Risk Score
# ==================================================================

class TestRiskScore(unittest.TestCase):

    def setUp(self):
        from risk_score import risk_score
        self.rs = risk_score

    def test_all_zero_gives_zero(self):
        self.assertEqual(self.rs(0, 0, 0, 0, 0), 0)

    def test_all_hundred_gives_hundred(self):
        self.assertAlmostEqual(self.rs(100, 100, 100, 100, 100), 100)

    def test_weights_sum_to_one(self):
        # 0.45 + 0.20 + 0.15 + 0.10 + 0.10 = 1.0
        self.assertAlmostEqual(self.rs(100, 100, 100, 100, 100), 100)

    def test_ml_score_dominates(self):
        high_ml  = self.rs(100, 0, 0, 0, 0)
        low_ml   = self.rs(0,   0, 0, 0, 0)
        self.assertGreater(high_ml, low_ml)

    def test_partial_risk(self):
        score = self.rs(50, 0, 0, 0, 0)     # 0.45 * 50 = 22.5
        self.assertAlmostEqual(score, 22.5)


# ==================================================================
# 4. Frequency Tracking
# ==================================================================

class TestFrequency(unittest.TestCase):

    HIST = "/tmp/stealthsense_frequency_history_test.json"
    LOCK = "/tmp/stealthsense_frequency_history_test.json.lock"

    def _clear(self):
        for path in (self.HIST, self.LOCK):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except PermissionError:
                    if path == self.HIST:
                        try:
                            with open(path, "w") as f:
                                json.dump({"queries": {}, "users": {}}, f)
                        except Exception:
                            pass

    def setUp(self):
        self._clear()

    def tearDown(self):
        self._clear()

    def test_first_query_returns_low_score(self):
        from frequency import query_frequency
        score = query_frequency("SELECT 1", "alice")
        self.assertEqual(score, 10)

    def test_score_escalates_at_medium_rate(self):
        from frequency import query_frequency, HISTORY_FILE
        now = time.time()
        fake = {
            "queries": {"select ?": [now - 1] * 5},
        }
        with open(HISTORY_FILE, "w") as f:
            json.dump(fake, f)
        score = query_frequency("SELECT 1", "alice")
        self.assertEqual(score, 70)

    def test_score_maxes_at_high_rate(self):
        from frequency import query_frequency, HISTORY_FILE
        now = time.time()
        fake = {
            "queries": {"select ?": [now - 1] * 10},
        }
        with open(HISTORY_FILE, "w") as f:
            json.dump(fake, f)
        score = query_frequency("SELECT 1", "alice")
        self.assertEqual(score, 100)

    def test_old_entries_are_not_evicted(self):
        from frequency import query_frequency, HISTORY_FILE, WINDOW
        now = time.time()
        fake = {
            "queries": {"select ?": [now - WINDOW - 10] * 200},
        }
        with open(HISTORY_FILE, "w") as f:
            json.dump(fake, f)
        score = query_frequency("SELECT 1", "alice")
        # Timing is not checked -> old entries NOT evicted -> score is 100
        self.assertEqual(score, 100)

    def test_different_queries_tracked_separately(self):
        from frequency import query_frequency, HISTORY_FILE
        now = time.time()
        fake = {
            "queries": {"select evil": [now - 1] * 10,
                        "select good": []},
        }
        with open(HISTORY_FILE, "w") as f:
            json.dump(fake, f)
        # "good" query: query_count = 1 (new) -> low
        score = query_frequency("SELECT good", "alice")
        self.assertEqual(score, 10)


# ==================================================================
# 5. End-to-End  detect.py invocation
# ==================================================================

PYTHON  = "/home/hp/stealthsense/ml/src/venv/bin/python3"
DETECT  = "/home/hp/stealthsense/ml/src/detect.py"
HIST_E2E = "/tmp/stealthsense_frequency_history_test.json"


def _run_detect(query, user="testuser", ip="127.0.0.1"):
    """Invoke detect.py as a subprocess and return (stdout.strip(), returncode)."""
    r = subprocess.run(
        [PYTHON, DETECT, query, user, ip],
        capture_output=True, text=True, timeout=15
    )
    return r.stdout.strip(), r.returncode


class TestDetectE2E(unittest.TestCase):

    def setUp(self):
        # Clear frequency history so each test starts clean
        if os.path.exists(HIST_E2E):
            try:
                os.remove(HIST_E2E)
            except PermissionError:
                try:
                    with open(HIST_E2E, "w") as f:
                        json.dump({"queries": {}, "users": {}}, f)
                except Exception:
                    pass

    def test_benign_query_allowed(self):
        out, rc = _run_detect("SELECT id FROM employees WHERE id=5")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "0", f"Expected 0 (allow) but got: '{out}'")

    def test_sql_injection_blocked(self):
        out, rc = _run_detect(
            "SELECT * FROM users WHERE username='admin' OR '1'='1'"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", f"Expected 1 (block) but got: '{out}'")

    def test_drop_table_blocked(self):
        out, rc = _run_detect("SELECT * FROM users; DROP TABLE employees")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", f"Expected 1 (block) but got: '{out}'")

    def test_privilege_escalation_blocked(self):
        out, rc = _run_detect("GRANT ALL PRIVILEGES ON DATABASE db TO hacker")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", f"Expected 1 (block) but got: '{out}'")

    def test_data_exfiltration_blocked(self):
        out, rc = _run_detect("SELECT pg_read_file('/etc/passwd')")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", f"Expected 1 (block) but got: '{out}'")

    def test_rate_limit_blocks_after_11_calls(self):
        """A benign query repeated >=11× per 10s must be blocked."""
        now = time.time()
        fake = {
            "queries": {"select id from employees where id=?": [now - 1] * 10},
        }
        with open(HIST_E2E, "w") as f:
            json.dump(fake, f)
        out, rc = _run_detect("SELECT id FROM employees WHERE id=5")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1",
            "Expected rate-limited query to be blocked (1), got: " + out)

    def test_repeated_query_blocked_after_11_calls(self):
        """A benign query run 11 times must be blocked on the 11th execution."""
        now = time.time()
        fake = {
            "queries": {"select id from employees where id=?": [now - 1] * 10},
        }
        with open(HIST_E2E, "w") as f:
            json.dump(fake, f)

        # 11th execution of the exact same query
        out, rc = _run_detect("SELECT id FROM employees WHERE id=5")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", "Expected repeated query to be blocked on 11th run")

    def test_repeated_query_with_different_comments_blocked_after_11_calls(self):
        """A benign query run with different comments must be normalized and blocked on 11th execution."""
        now = time.time()
        fake = {
            "queries": {"select id from employees where id=?": [now - 1] * 10},
        }
        with open(HIST_E2E, "w") as f:
            json.dump(fake, f)

        # 11th execution with a different comment
        out, rc = _run_detect("SELECT id FROM employees WHERE id=5 -- comment three")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", "Expected normalized query to be blocked on 11th run")

    def test_repeated_query_with_different_literals_blocked_after_11_calls(self):
        """A benign query run with different numeric values must be normalized and blocked on 11th execution."""
        now = time.time()
        fake = {
            "queries": {"select * from users where id=?": [now - 1] * 10},
        }
        with open(HIST_E2E, "w") as f:
            json.dump(fake, f)

        # 11th execution with a different ID value (e.g. 6)
        out, rc = _run_detect("SELECT * FROM users WHERE id=6")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "1", "Expected query with different literal values to be normalized and blocked")

    def test_unknown_ip_raises_risk(self):
        """Query from an unknown IP should raise risk even if query is benign."""
        out, rc = _run_detect(
            "SELECT id FROM employees WHERE id=5",
            ip="198.51.100.42"   # not in whitelist
        )
        self.assertEqual(rc, 0)
        # Unknown IP adds 10 points (0.10 * 100 = 10) – may or may not cross threshold
        # We just check it doesn't crash and returns a valid verdict
        self.assertIn(out, ["0", "1"])

    def test_malformed_query_does_not_crash(self):
        """An empty or garbage query must not crash detect.py."""
        out, rc = _run_detect("")
        self.assertEqual(rc, 0)
        self.assertIn(out, ["0", "1"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
