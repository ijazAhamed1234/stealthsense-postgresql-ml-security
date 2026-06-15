/*
 * stealthsense.c
 * StealthSense - PostgreSQL Security Extension
 */

#include "postgres.h"
#include "fmgr.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "libpq/libpq-be.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "tcop/utility.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>

PG_MODULE_MAGIC;

/* Extension enabled state (settable via GUC) */
static bool ss_enabled = true;

/* Max time in milliseconds to wait for the ML engine (settable via GUC) */
static int ss_timeout_ms = 3000;

/* Bypass ML checks for superusers (settable via GUC) */
static bool ss_bypass_superuser = false;

void _PG_init(void);
void _PG_fini(void);

/* Saved pointers to previous hooks for chaining */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

static void stealth_executor(QueryDesc *queryDesc, int eflags);
static void stealth_utility(PlannedStmt *pstmt,
                            const char *queryString,
                            bool readOnlyTree,
                            ProcessUtilityContext context,
                            ParamListInfo params,
                            QueryEnvironment *queryEnv,
                            DestReceiver *dest,
                            QueryCompletion *qc);

static int detect_query(const char *query, const char *user, const char *ip);
static void log_event(const char *user, const char *ip, const char *query);

/* Called when PostgreSQL loads the shared library */
void
_PG_init(void)
{
    DefineCustomBoolVariable(
        "stealthsense.enabled",
        "Enable or disable StealthSense query interception.",
        NULL,
        &ss_enabled,
        true,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    DefineCustomIntVariable(
        "stealthsense.timeout_ms",
        "Milliseconds to wait for the ML detector before allowing the query.",
        NULL,
        &ss_timeout_ms,
        3000,
        50,
        30000,
        PGC_SUSET,
        GUC_UNIT_MS,
        NULL, NULL, NULL
    );

    DefineCustomBoolVariable(
        "stealthsense.bypass_superuser",
        "Skip ML inspection for superuser queries.",
        NULL,
        &ss_bypass_superuser,
        false,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Install executor and utility hooks */
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = stealth_executor;

    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = stealth_utility;
}

/* Called when the library is unloaded */
void
_PG_fini(void)
{
    ExecutorStart_hook = prev_ExecutorStart;
    ProcessUtility_hook = prev_ProcessUtility;
}

/* Intercepts DML queries (SELECT, INSERT, UPDATE, DELETE) */
static void
stealth_executor(QueryDesc *queryDesc, int eflags)
{
    const char *query;
    const char *user;
    const char *ip;
    int suspicious;

    if (!ss_enabled || queryDesc == NULL || queryDesc->sourceText == NULL)
    {
        if (prev_ExecutorStart)
            prev_ExecutorStart(queryDesc, eflags);
        else
            standard_ExecutorStart(queryDesc, eflags);
        return;
    }

    query = queryDesc->sourceText;
    user = GetUserNameFromId(GetUserId(), false);

    if (ss_bypass_superuser && superuser())
    {
        if (prev_ExecutorStart)
            prev_ExecutorStart(queryDesc, eflags);
        else
            standard_ExecutorStart(queryDesc, eflags);
        return;
    }

    if (MyProcPort && MyProcPort->remote_host)
        ip = MyProcPort->remote_host;
    else
        ip = "unknown";

    suspicious = detect_query(query, user, ip);

    if (suspicious)
    {
        log_event(user, ip, query);
        ereport(ERROR,
                (errmsg("StealthSense: blocked suspicious query from user=%s ip=%s", user, ip)));
    }

    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/* Forks Python detector in a child process and reads verdict from pipe */
static int
detect_query(const char *query, const char *user, const char *ip)
{
    int pipefd[2];
    pid_t pid;
    char result[32];
    int nbytes;
    fd_set rfds;
    struct timeval tv;
    int sel_ret;
    int child_status;

    if (pipe(pipefd) == -1)
    {
        elog(WARNING, "StealthSense: pipe() failed");
        return 0; /* fail-safe: allow query */
    }

    pid = fork();
    if (pid == -1)
    {
        elog(WARNING, "StealthSense: fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return 0; /* fail-safe: allow query */
    }

    /* Child Process */
    if (pid == 0)
    {
        int err_log;
        char *const argv[] = {
            "/home/hp/stealthsense/ml/src/venv/bin/python3",
            "/home/hp/stealthsense/ml/src/detect.py",
            (char *) query,
            (char *) user,
            (char *) ip,
            NULL
        };

        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        /* Redirect stderr to logs/error.log to capture python loader/execv errors */
        err_log = open("/home/hp/stealthsense/logs/error.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (err_log != -1)
        {
            dup2(err_log, STDERR_FILENO);
            close(err_log);
        }

        execv(argv[0], argv);
        _exit(1); /* execv failed */
    }

    /* Parent Process */
    close(pipefd[1]);

    FD_ZERO(&rfds);
    FD_SET(pipefd[0], &rfds);
    tv.tv_sec = ss_timeout_ms / 1000;
    tv.tv_usec = (ss_timeout_ms % 1000) * 1000;

    sel_ret = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);

    memset(result, 0, sizeof(result));
    nbytes = 0;

    if (sel_ret > 0)
    {
        nbytes = (int) read(pipefd[0], result, sizeof(result) - 1);
    }
    else
    {
        /* Timeout or select error - kill the child and fail-safe */
        elog(WARNING, "StealthSense: ML detector timed out after %d ms - allowing query", ss_timeout_ms);
        kill(pid, SIGKILL);
    }

    close(pipefd[0]);
    waitpid(pid, &child_status, 0);

    if (nbytes <= 0)
        return 0;

    return atoi(result); /* 1 = block, 0 = allow */
}

/* Appends a sanitized single-line query event to logs/detections.log */
static void
log_event(const char *user, const char *ip, const char *query)
{
    FILE *fp;
    const char *p;
    char c;

    fp = fopen("/home/hp/stealthsense/logs/detections.log", "a");
    if (fp == NULL)
        return;

    fprintf(fp, "USER=%s IP=%s QUERY=", user, ip);

    for (p = query; (c = *p) != '\0'; p++)
    {
        if (c == '\n' || c == '\r' || c == '\t')
            fputc(' ', fp);
        else
            fputc(c, fp);
    }

    fputc('\n', fp);
    fclose(fp);
}

/* Intercepts DDL/Utility statements (DROP TABLE, CREATE TABLE, ALTER TABLE, etc.) */
static void
stealth_utility(PlannedStmt *pstmt,
                const char *queryString,
                bool readOnlyTree,
                ProcessUtilityContext context,
                ParamListInfo params,
                QueryEnvironment *queryEnv,
                DestReceiver *dest,
                QueryCompletion *qc)
{
    const char *user;
    const char *ip;
    int suspicious;

    if (!ss_enabled || queryString == NULL)
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        return;
    }

    user = GetUserNameFromId(GetUserId(), false);

    if (ss_bypass_superuser && superuser())
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
        return;
    }

    if (MyProcPort && MyProcPort->remote_host)
        ip = MyProcPort->remote_host;
    else
        ip = "unknown";

    suspicious = detect_query(queryString, user, ip);

    if (suspicious)
    {
        log_event(user, ip, queryString);
        ereport(ERROR,
                (errmsg("StealthSense: blocked suspicious query from user=%s ip=%s", user, ip)));
    }

    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}