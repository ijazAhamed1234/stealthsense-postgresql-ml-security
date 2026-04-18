#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include "tcop/utility.h"

static ProcessUtility_hook_type prev_ProcessUtility = NULL;
PG_MODULE_MAGIC;

/* Hook */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;

/* -------- GLOBAL TRACKING -------- */
static int prev_val = -1;
static int sequence_count = 0;

static char last_query[2048] = "";
static int repeat_count = 0;

/* -------- EXTRACT NUMBER -------- */
static int extract_value(const char *query)
{
    for (int i = 0; query[i]; i++)
        if (isdigit(query[i]))
            return atoi(&query[i]);
    return -1;
}

/* -------- ML -------- */
static int call_ml_model(const char *query)
{
    char command[4096];
    char result[16] = "0";

    snprintf(command, sizeof(command),
        "/home/hp/stealthsense/ml/venv/bin/python3 /home/hp/stealthsense/ml/detect.py \"%s\"",
        query);

    FILE *fp = popen(command, "r");
    if (!fp) return 0;

    fgets(result, sizeof(result), fp);
    pclose(fp);

    return atoi(result);
}

/* -------- MAIN ANALYSIS -------- */
static void analyze_query(const char *query)
{
    char q[2048];

    /* normalize */
    for (int i = 0; query[i] && i < sizeof(q)-1; i++)
        q[i] = tolower(query[i]);
    q[strlen(query)] = '\0';

    /* ================= REPEAT ================= */
    if (strcmp(last_query, q) == 0)
        repeat_count++;
    else
    {
        repeat_count = 1;
        strncpy(last_query, q, sizeof(last_query)-1);
    }

    if (repeat_count >= 5)
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Repeated Query Attack")));
    }

    /* ================= SEQUENCE ================= */
    int val = extract_value(q);

    if (val != -1)
    {
        if (prev_val != -1 && val == prev_val + 1)
            sequence_count++;
        else
            sequence_count = 1;

        prev_val = val;

        if (sequence_count >= 5)
        {
            ereport(ERROR,
                (errmsg("STEALTHSENSE BLOCKED: Sequential Data Extraction")));
        }
    }

    /* ================= SQL INJECTION ================= */
    if (strstr(q, "or 1=1") || strstr(q, "--") || strstr(q, "union"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: SQL Injection")));
    }

    /* ================= DATA DUMP ================= */
    if (strstr(q, "select * from users") && !strstr(q, "where"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Full Table Data Dump")));
    }

    /* ================= SENSITIVE DATA ================= */
    if (strstr(q, "password"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Sensitive Data Access")));
    }

    /* ================= DROP BLOCK ================= */
    if (strstr(q, "drop table") || strstr(q, "drop database"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Dangerous DROP Operation")));
    }

    /* ================= DELETE BLOCK ================= */
    if (strstr(q, "delete") && !strstr(q, "where"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Mass DELETE Attempt")));
    }

    /* Extra protection */
    if (strstr(q, "delete") && strstr(q, "1=1"))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: DELETE Injection Attack")));
    }

    /* ================= ML ================= */
    if (call_ml_model(q) == 1)
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: ML Anomaly")));
    }
}
static void stealth_ProcessUtility(PlannedStmt *pstmt,
                                  const char *queryString,
                                  bool readOnlyTree,
                                  ProcessUtilityContext context,
                                  ParamListInfo params,
                                  QueryEnvironment *queryEnv,
                                  DestReceiver *dest,
                                  QueryCompletion *qc)
{
    if (queryString)
    {
        char q[2048];

        /* normalize */
        for (int i = 0; queryString[i] && i < sizeof(q)-1; i++)
            q[i] = tolower(queryString[i]);
        q[strlen(queryString)] = '\0';

        /* 🔴 BLOCK DROP */
        if (strstr(q, "drop table") || strstr(q, "drop database"))
        {
            ereport(ERROR,
                (errmsg("STEALTHSENSE BLOCKED: DROP Operation Detected")));
        }

        /* 🔴 BLOCK DELETE MASS */
        if (strstr(q, "delete") && !strstr(q, "where"))
        {
            ereport(ERROR,
                (errmsg("STEALTHSENSE BLOCKED: Mass DELETE Detected")));
        }
    }

    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree,
                            context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv, dest, qc);
}
/* -------- HOOK -------- */
static void stealth_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    if (queryDesc->sourceText)
        analyze_query(queryDesc->sourceText);

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/* -------- INIT -------- */
void _PG_init(void)
{
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = stealth_ExecutorStart;

    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = stealth_ProcessUtility;

    elog(LOG, "🔥 StealthSense FULL HOOK Loaded");
}

/* -------- FINI -------- */
void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
    ProcessUtility_hook = prev_ProcessUtility;
}