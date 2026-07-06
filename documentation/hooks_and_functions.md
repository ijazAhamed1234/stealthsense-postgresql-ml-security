# StealthSense PostgreSQL Extension: Hooks & Functions Documentation

This document explains the architecture of the **StealthSense** security extension, detailing how PostgreSQL hooks intercept commands, how the C extension communicates with the Python detection service, and the function of each script/module in the codebase.

---

## 1. Architectural Overview

StealthSense operates as an inline query firewall for PostgreSQL. It splits responsibilities between:
1. **The C Extension (`stealthsense.c`)**: Runs inside the PostgreSQL backend process. It hooks into the query parser/executor, intercepts incoming queries, captures context (user, IP), forks the Python detector, and blocks execution if a threat is detected.
2. **The Python Detector (`detect.py`)**: Runs as a separate process spawned by the C extension. It extracts query features, checks an IP whitelist, analyzes rate patterns, queries a Random Forest ML model, and produces a composite risk score (0-100).

---

## 2. PostgreSQL Hooks Explained

Hooks in PostgreSQL are global function pointers that allow extensions to intercept core server events. StealthSense registers two hooks:

### A. `ExecutorStart_hook`
- **Interception Target**: Standard Data Manipulation Language (DML) statements (e.g., `SELECT`, `INSERT`, `UPDATE`, `DELETE`).
- **How it works**: Before PostgreSQL plans and starts executing any DML query, the server calls `ExecutorStart_hook`. StealthSense intercepts this call, retrieves the SQL query text from `queryDesc->sourceText`, and retrieves the client's IP and username.
- **Handling**: If the query is flagged as suspicious by `detect_query`, the hook throws an `ereport(ERROR)`, which aborts the query execution and rolls back the current transaction. If allowed, it forwards execution to the next hook in the chain.

### B. `ProcessUtility_hook`
- **Interception Target**: Data Definition Language (DDL) and utility statements (e.g., `DROP TABLE`, `CREATE TABLE`, `ALTER TABLE`, `GRANT`, `COPY`, etc.).
- **How it works**: These statements bypass the standard executor. Instead, they are handled by the utility processor. StealthSense hooks into `ProcessUtility_hook` to intercept these commands.
- **Handling**: Captures the raw utility query string. If a malicious utility query is detected (like an unauthorized `DROP TABLE` or `GRANT ALL`), it halts execution immediately via `ereport(ERROR)`.

### C. Hook Chain Preservation
PostgreSQL allows multiple extensions to hook into the same events. To avoid breaking other extensions (e.g., `pg_stat_statements`), StealthSense follows standard hook-preservation practices:
1. When loaded, it saves the existing hook pointer in local variables:
   ```c
   static ExecutorStart_hook_type prev_ExecutorStart_hook = NULL;
   static ProcessUtility_hook_type prev_ProcessUtility_hook = NULL;
   ```
2. It sets the global hook pointer to its custom function.
3. In the custom function, if the query is allowed, it invokes the saved previous hook:
   ```c
   if (prev_ExecutorStart_hook)
       prev_ExecutorStart_hook(queryDesc, eflags);
   else
       standard_ExecutorStart(queryDesc, eflags);
   ```

---

## 3. C Functions inside `stealthsense.c`

### `_PG_init`
- **Purpose**: Called automatically when the PostgreSQL server preloads the extension (via `shared_preload_libraries`).
- **Functionality**:
  - Registers the custom Grand Unified Configuration (GUC) parameters (`stealthsense.enabled`, `stealthsense.bypass_superuser`).
  - Saves the previous hook addresses and registers the custom hooks.

### `_PG_fini`
- **Purpose**: Called if the extension is unloaded.
- **Functionality**: Restores the original hooks.

### `detect_query`
- **Purpose**: Orchestrates communication with the Python detection script and makes the final ALLOW/BLOCK decision.
- **Functionality**:
  1. **Superuser Bypass**: Checks `stealthsense.bypass_superuser`. If `true` and the current user is a superuser, it returns `0` (allow) immediately.
  2. **Interprocess Pipe**: Creates a POSIX pipe (`pipe()`) to read the child process's stdout.
  3. **Forking**: Calls `fork()`.
     - **Child Process**:
       - Redirects `stdout` to the write end of the pipe.
       - Redirects `stderr` to a persistent file (`logs/error.log`) to capture startup/module issues.
       - Invokes the virtual environment's Python interpreter to run `detect.py` using `execv()`.
     - **Parent Process (PostgreSQL)**:
       - Performs a blocking `read()` on the pipe to wait for the child's response.
       - Reaps the child process, parses its output (`0` or `1`), and returns the decision.

### `log_event`
- **Purpose**: Writes blocked query details to the audit log (`logs/detections.log`).
- **Functionality**: Sanitizes the query string by replacing newlines (`\n`, `\r`) and tab characters (`\t`) with spaces. This ensures that every audit log entry is written as a single line, preserving log parser formatting.

---

## 4. Python Detection System Functions

### A. `detect.py`
The orchestration script for the ML classification layer.
- `main()`: Resolves the python environment path (injects virtual environment `site-packages`), processes command-line arguments (query, user, client IP), runs feature extraction, and computes risk.
- `calculate_risk()`: Gathers scores from the feature extractor, whitelist, frequency tracker, and Random Forest model, and applies weights to compute the composite risk score.
- Enforces the decision thresholds:
  - **Risk < 25**: `ALLOW`
  - **25 <= Risk <= 40**: `LOG` (warn)
  - **Risk > 40**: `BLOCK`

### B. `frequency.py`
Historical query frequency tracker.
- `query_frequency()`: Retrieves previous execution history for the query. Appends the new execution. Timing windows and user-level constraints are not checked.
- **Locking (`_load_history` and `_save_history`)**: Acquires an exclusive file lock (`fcntl.flock()`) on `/tmp/stealthsense_frequency_history.json.lock` during reads and writes to prevent data corruption by concurrent backend processes.
- **Throttling Thresholds**:
  - $\ge 6$ requests: Returns a score of `70` (triggers warning/LOG verdict).
  - $\ge 11$ requests: Returns a score of `100` (forces an early BLOCK exit).

### C. `feature_extractor.py`
Extracts static lexical features from the query.
- `extract_features()`: Measures conditions, digits, joins, subqueries, length, and checks for dangerous SQL keywords (e.g. `UNION`, `DROP`, `INFORMATION_SCHEMA`).
- `clean_query()`: Normalizes incoming queries by removing comments (both `--` single-line and `/* ... */` multi-line) to prevent SQL obfuscation bypasses.

### D. `whitelist.py`
Validates connection source IPs.
- `is_whitelisted()`: Checks if the client IP is listed in `ml/data/whitelist_ips.txt` (skips blank and comment lines starting with `#`). Uses a hash set lookup for $O(1)$ performance.
