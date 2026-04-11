# stealthsense-postgresql-ml-security
#**Explanation**
#User Query
#A SQL query is sent to the PostgreSQL database.
#Extension Intercepts Query
#The C-based PostgreSQL extension captures the query before execution.
#Feature Extraction
#Important features like query length, number of digits, conditions, and WHERE clause are extracted.
#Machine Learning Check
#The query is analyzed using an Isolation Forest model to detect anomalies.
#Behavior Analysis
#Repeated queries → detected as attack
#Sequential queries (1,2,3…) → detected as data extraction
#Decision Engine
#Normal query → Allowed
#Suspicious query → Blocked
#Final Output
#The system either executes the query or blocks it with a security alert.
