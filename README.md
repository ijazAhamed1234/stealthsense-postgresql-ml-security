# stealthsense-postgresql-ml-security
1. **User Query**
   A SQL query is sent to the PostgreSQL database.

2. **Extension Intercepts Query**
   The C-based PostgreSQL extension captures the query before execution.

3. **Feature Extraction**
   Important features like query length, number of digits, conditions, and WHERE clause are extracted.

4. **Machine Learning Check**
   The query is analyzed using an Isolation Forest model to detect anomalies.

5. **Behavior Analysis**

   * Repeated queries → detected as attack
   * Sequential queries (1,2,3…) → detected as data extraction

6. **Decision Engine**

   * Normal query → Allowed
   * Suspicious query → Blocked

7. **Final Output**
   The system either executes the query or blocks it with a security alert.

---
