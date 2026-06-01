#include "postgres.h"

#include "fmgr.h"

#include "executor/executor.h"

#include "miscadmin.h"

#include "libpq/libpq.h"

#include "utils/builtins.h"

#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

#include <sys/types.h>

#include <sys/wait.h>

#include <fcntl.h>


PG_MODULE_MAGIC;


/* Original Hook */

static ExecutorStart_hook_type prev_ExecutorStart = NULL;


/* Function */

void _PG_init(void);

void _PG_fini(void);

static void stealth_executor(

QueryDesc *queryDesc,

int eflags

);

static int detect_query(

const char *query,

const char *user,

const char *ip

);

static void log_event(

const char *user,

const char *ip,

const char *query

);



/* Init */

void _PG_init(void)
{
    prev_ExecutorStart =
        ExecutorStart_hook;

    ExecutorStart_hook =
        stealth_executor;
}



/* Cleanup */

void _PG_fini(void)
{
    ExecutorStart_hook =
        prev_ExecutorStart;
}



/* Main Hook */

static void stealth_executor(

QueryDesc *queryDesc,

int eflags

)
{
    const char *query;

    const char *user;

    const char *ip;

    int suspicious;


    if(queryDesc == NULL ||
       queryDesc->sourceText == NULL)
    {

        if(prev_ExecutorStart)
            prev_ExecutorStart(
                queryDesc,
                eflags
            );

        return;
    }


    query =
        queryDesc->sourceText;


    user =
        GetUserNameFromId(

        GetUserId(),

        false

        );


    if(MyProcPort &&
       MyProcPort->remote_host)
    {

        ip =
        MyProcPort->remote_host;

    }
    else
    {

        ip="unknown";

    }


    suspicious =
        detect_query(

        query,

        user,

        ip

        );


    if(suspicious)
    {
        log_event(

        user,

        ip,

        query

        );

        ereport(

        ERROR,

        (

        errmsg(

        "StealthSense blocked suspicious query"

        )

        )

        );
    }


    if(prev_ExecutorStart)

        prev_ExecutorStart(

        queryDesc,

        eflags

        );

    else

        standard_ExecutorStart(

        queryDesc,

        eflags

        );
}



/* Python ML Call */

static int detect_query(

const char *query,

const char *user,

const char *ip

)
{
    int pipefd[2];
    pid_t pid;
    char result[32];
    int status;
    int bytes_read;

    if (pipe(pipefd) == -1)
    {
        elog(WARNING, "ML detector pipe failed");
        return 0;
    }

    pid = fork();
    if (pid == -1)
    {
        elog(WARNING, "ML detector fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (pid == 0)
    {
        /* Child process */
        int dev_null;
        char *const argv[] = {
            "/home/hp/stealthsense/ml/src/venv/bin/python3",
            "/home/hp/stealthsense/ml/src/detect.py",
            (char *)query,
            (char *)user,
            (char *)ip,
            NULL
        };

        close(pipefd[0]); /* Close unused read end */
        dup2(pipefd[1], STDOUT_FILENO); /* Redirect stdout to pipe */
        close(pipefd[1]);

        /* Redirect stderr to /dev/null to avoid cluttering postgres logs */
        dev_null = open("/dev/null", O_WRONLY);
        if (dev_null != -1)
        {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }

        execv(argv[0], argv);
        /* If execv returns, an error occurred */
        exit(1);
    }
    else
    {
        /* Parent process */
        close(pipefd[1]); /* Close unused write end */

        memset(result, 0, sizeof(result));
        bytes_read = read(pipefd[0], result, sizeof(result) - 1);
        close(pipefd[0]);

        waitpid(pid, &status, 0);

        if (bytes_read <= 0)
            return 0;

        return atoi(result);
    }
}



/* Logging */

static void log_event(

const char *user,

const char *ip,

const char *query

)
{
    FILE *fp;


    fp=fopen(

"/home/hp/stealthsense/logs/detections.log",

"a"

);


    if(fp==NULL)

        return;


    fprintf(

    fp,

"USER=%s IP=%s QUERY=%s\n",

    user,

    ip,

    query

    );


    fclose(fp);
}