/* Internal interface shared by addon.c, hooks.c and runner.c. */
#ifndef LIBMASSCAN_H
#define LIBMASSCAN_H

#include <pthread.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

enum lm_event_type {
    LM_EV_RESULT,
    LM_EV_BANNER,
    LM_EV_PROGRESS,
    LM_EV_LOG,
    LM_EV_DONE
};

struct lm_event {
    enum lm_event_type type;

    /* LM_EV_RESULT, LM_EV_BANNER */
    char ip[64];
    unsigned port;
    unsigned ip_proto;
    unsigned ttl;
    int status;              /* enum PortStatus */
    char reason[32];         /* TCP flags as text, TCP results only */
    char mac[18];            /* ARP results only */
    char service[32];        /* LM_EV_BANNER: application protocol name */
    time_t timestamp;

    /* LM_EV_PROGRESS */
    double percent;
    double rate;
    uint64_t count;
    uint64_t total;
    uint64_t syns;
    uint64_t synacks;
    uint64_t tcbs;
    int64_t remaining;       /* seconds left in the wait window, -1 if scanning */

    /* LM_EV_LOG */
    int level;

    /* LM_EV_DONE */
    int failed;
    int exit_code;
    int has_resume;
    uint64_t resume_index;

    /* Owned text: banner bytes, log message, or error message. */
    char *text;
    size_t text_len;
};

#define LM_ERROR_LINES 8

struct lm_scan {
    pthread_mutex_t lock;
    struct lm_event *events;
    size_t count;
    size_t capacity;
    int notify_pending;

    void *tsfn;              /* napi_threadsafe_function */

    int argc;
    char **argv;

    /* The last level-0 log lines. They become the error message. */
    char error_lines[LM_ERROR_LINES][256];
    unsigned error_line_count;
};

struct lm_run_result {
    int failed;
    int exit_code;           /* set when masscan called exit() */
    int has_resume;
    uint64_t resume_index;
    char message[256];       /* set by the runner for its own errors */
};

/* The scan that receives events. NULL when no scan runs. */
extern struct lm_scan *volatile lm_current;

/* Exit trap state (hooks.c, used by runner.c). */
extern __thread jmp_buf *lm_exit_jmp;
extern __thread int lm_exit_code;
extern volatile int lm_threads_started;
extern volatile int lm_poisoned;

/* The scan position from the most recent status tick (hooks.c). */
extern volatile uint64_t lm_last_index;

/* hooks.c */
void lm_push(struct lm_scan *scan, struct lm_event *ev);
void lm_log_text(int level, const char *text);
void lm_set_verbosity(int level);

/* runner.c */
int lm_run(int argc, char **argv, struct lm_run_result *result);
void lm_reset_globals(void);
void lm_request_stop(int force);
void lm_wake_receivers(void);

/* addon.c: finishes a scan and hands the done event to JavaScript. */
void lm_complete(struct lm_scan *scan, const struct lm_run_result *result);

#endif
