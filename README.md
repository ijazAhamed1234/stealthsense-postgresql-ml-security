# StealthSense PostgreSQL ML Security Extension

# Overview

StealthSense is a PostgreSQL security extension designed to detect and block suspicious database activities using machine learning, behavioral analysis, and query inspection techniques. The system integrates directly into PostgreSQL through a C-based extension and analyzes queries before execution.

The primary goal is to identify abnormal database behavior, SQL injection attempts, privilege escalation, data exfiltration attempts, and suspicious query patterns while minimizing false positives.

---

# Problem Statement

Traditional database security mechanisms mostly depend on static rules and predefined signatures. Modern attacks frequently bypass these defenses using stealthy SQL injections, enumeration techniques, and abnormal query sequences.

StealthSense addresses this problem by combining:

- PostgreSQL query interception
- Machine learning anomaly detection
- User behavior analysis
- Query frequency monitoring
- IP whitelist validation
- Risk-based blocking

---

# System Workflow
```text
User Query
    ↓

PostgreSQL Extension Hook
(C-Based Interception)

    ↓

Feature Extraction

    ↓

Behavior Analysis
(User + Frequency)

    ↓

Machine Learning Detection

    ↓

Risk Scoring Engine

    ↓

Decision Layer

ALLOW / LOG / BLOCK

    ↓

Database Execution
```
---

# Architecture Components

1. Query Interception Layer

The PostgreSQL extension intercepts SQL queries before execution using PostgreSQL hooks.

Responsibilities:

- Capture query text
- Capture user information
- Capture client IP
- Forward query for analysis

---

2. Feature Extraction Engine

Features extracted from incoming queries:

- Query length
- Number of digits
- Number of conditions
- WHERE clause existence
- Number of joins
- Query complexity
- Suspicious keywords
- Multiple statement detection

---

3. Machine Learning Engine

Machine learning is used to classify suspicious database behavior.

Model:

- Random Forest Classifier

Training Inputs:

- Normal SQL queries
- SQL injection attacks
- Enumeration attacks
- Privilege escalation attempts
- Data exfiltration queries

---

4. Behavioral Analysis

The system monitors user behavior patterns.

Checks include:

- Repeated queries
- Query frequency spikes
- Sequential extraction patterns
- Abnormal table access
- Unusual query complexity

---

5. Risk Scoring Layer

The composite risk score is calculated as a weighted sum of five security signals (each ranging from 0 to 100):

$$Risk = 0.45 \times ML\_Score + 0.20 \times Keyword\_Score + 0.15 \times Frequency\_Score + 0.10 \times IP\_Score + 0.10 \times Complexity\_Score$$

### Composite Signals:
1. **Machine Learning Score (45% weight)**: Probability (0-100) estimated by the Random Forest classifier based on query structure.
2. **Keyword Risk (20% weight)**: Calculated as `min(keyword_hits * 10, 100)`, flagging known dangerous SQL words (e.g. `UNION`, `DROP`, `pg_read_file`, `--`).
3. **Query Frequency (15% weight)**: Measured using historical query count (no timing window or user-level checks).
   - Normal traffic (count $\le 5$): score 10
   - Moderate count ($> 5$ requests, i.e. $\ge 6$): score 70 (triggers warning/LOG verdict)
   - Extreme count ($> 10$ requests, i.e. $\ge 11$): score 100 (automatically overrides and forces a hard block).
4. **IP Trust Score (10% weight)**: 0 if client IP is present in `whitelist_ips.txt` (e.g. `[local]`, `127.0.0.1`); 100 for unknown external IPs.
5. **Query Complexity (10% weight)**: Computed as `min(stacked_queries * 20 + joins * 10, 100)`.

### Decision Thresholds:
- **Risk < 25**: **ALLOW** (query runs normally)
- **25 $\le$ Risk $\le$ 40**: **LOG** (allowed to run, but warning is recorded in `detections.log`)
- **Risk > 40**: **BLOCK** (aborted before execution, error returned to client, and logged in `detections.log`)
---

# Folder Structure
```text
stealthsense/

├── extension/
│   ├── stealthsense.c
│   ├── Makefile
│   ├── stealthsense.control
│   └── stealthsense--1.0.sql
│
├── ml/
│   ├── src/
│   ├── data/
│   ├── models/
│   └── requirements.txt
│
├── config/
│   └── whitelist_ips.txt
│
├── logs/
│
└── README.md
```
---

Installation

Install dependencies:
```text
pip install pandas numpy scikit-learn joblib

Train model:

cd ml/src

python3 train_model.py

Compile PostgreSQL extension:

cd extension

make

sudo make install

Enable extension:

shared_preload_libraries='stealthsense'

Restart PostgreSQL:

sudo systemctl restart postgresql

Create extension:

CREATE EXTENSION stealthsense;
```
---

Supported Attack Detection

The system is designed to detect:

- SQL Injection
- UNION Attacks
- Database Enumeration
- Table Enumeration
- Column Enumeration
- Data Exfiltration
- Bulk Deletes
- Stacked Queries

---

Example Detection Flow
```text
Normal Query:

SELECT * FROM users WHERE id=5;

Output:

ALLOW

Suspicious Query:

SELECT * FROM users;
DROP TABLE employee;

Output:

BLOCK
```
---

Future Enhancements

- Session window analysis
- Deep learning sequence models
- Dynamic user profiling
- Adaptive threshold tuning
- Dashboard visualization
- Real-time alerting

