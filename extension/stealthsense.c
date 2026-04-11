#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

PG_MODULE_MAGIC;

/* Hook */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;

/* -------- GLOBAL -------- */
static char last_query[2048] = "";
static int repeat_count = 0;

static int prev_id = -1;
static int sequence_count = 0;

/* -------- EXTRACT VALUE -------- */
static int extract_value(const char *query)
{
    for (int i = 0; query[i]; i++)
        if (isdigit(query[i]))
            return atoi(&query[i]);
    return -1;
}

/* -------- ML CALL -------- */
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

/* -------- SAME QUERY DETECTION -------- */
static int detect_repeat_query(const char *query)
{
    if (strcmp(last_query, query) == 0)
        repeat_count++;
    else
    {
        repeat_count = 1;
        strncpy(last_query, query, sizeof(last_query)-1);
    }

    return (repeat_count >= 5);
}

/* -------- SEQUENCE DETECTION -------- */
static int detect_sequence(const char *query)
{
    int current_id = extract_value(query);

    if (current_id == -1)
        return 0;

    if (prev_id != -1 && current_id == prev_id + 1)
        sequence_count++;
    else
        sequence_count = 1;

    prev_id = current_id;

    return (sequence_count >= 5);
}

/* -------- MAIN ANALYSIS -------- */
static void analyze_query(const char *query)
{
    /* 🔴 SAME QUERY */
    if (detect_repeat_query(query))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Repeated Query Attack")));
    }

    /* 🔴 SEQUENCE */
    if (detect_sequence(query))
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: Sequential Extraction Detected")));
    }

    /* 🔴 ML */
    int anomaly = call_ml_model(query);

    if (anomaly == 1)
    {
        ereport(ERROR,
            (errmsg("STEALTHSENSE BLOCKED: ML Anomaly Detected")));
    }
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

    elog(LOG, "🔥 StealthSense Loaded");
}

/* -------- FINI -------- */
void _PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
}