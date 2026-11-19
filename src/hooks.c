/* Replaces upstream logging, status and output with events. Not compiled with the shim. */
#include "libmasscan.h"

#if defined(__GLIBC__) || defined(__APPLE__)
#include <execinfo.h>
#define LM_HAVE_BACKTRACE 1
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "masscan.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "main-status.h"
#include "massip-addr.h"
#include "output.h"
#include "pixie-timer.h"
#include "util-logger.h"

/* Defined in upstream main.c (compiled through runner.c). */
extern unsigned volatile is_tx_done;
extern unsigned volatile is_rx_done;
extern time_t global_now;

/* Upstream output.c, compiled under new names by masscan-output.c. */
void lm_orig_output_report_status(struct Output *out, time_t timestamp,
    int status, ipaddress ip, unsigned ip_proto, unsigned port,
    unsigned reason, unsigned ttl, const unsigned char mac[6]);
void lm_orig_output_report_banner(struct Output *out, time_t timestamp,
    ipaddress ip, unsigned ip_proto, unsigned port, unsigned proto,
    unsigned ttl, const unsigned char *px, unsigned length);

struct lm_scan *volatile lm_current = NULL;

__thread jmp_buf *lm_exit_jmp = NULL;
__thread int lm_exit_code = 0;
volatile int lm_threads_started = 0;
volatile int lm_poisoned = 0;
volatile uint64_t lm_last_index = 0;

static int lm_verbosity = 0;

/* addon.c: asks the main thread to drain the queue. */
void lm_notify(struct lm_scan *scan);

void
lm_push(struct lm_scan *scan, struct lm_event *ev)
{
    if (scan == NULL) {
        free(ev->text);
        return;
    }

    pthread_mutex_lock(&scan->lock);
    if (scan->count == scan->capacity) {
        size_t capacity = scan->capacity ? scan->capacity * 2 : 64;
        struct lm_event *events = realloc(scan->events,
                                          capacity * sizeof(*events));
        if (events == NULL) {
            /* Drop the event. Do not stop the scan for a lost event. */
            pthread_mutex_unlock(&scan->lock);
            free(ev->text);
            return;
        }
        scan->events = events;
        scan->capacity = capacity;
    }
    scan->events[scan->count++] = *ev;

    /* One wake-up per batch, not per event. */
    if (!scan->notify_pending) {
        scan->notify_pending = 1;
        lm_notify(scan);
    }
    pthread_mutex_unlock(&scan->lock);
}

static char *
lm_strndup(const char *text, size_t length)
{
    char *copy = malloc(length + 1);
    if (copy) {
        memcpy(copy, text, length);
        copy[length] = '\0';
    }
    return copy;
}

static void
lm_log_line(int level, const char *line, size_t length)
{
    struct lm_scan *scan = lm_current;
    struct lm_event ev;

    /* Remove trailing white space. Masscan pads status lines. */
    while (length && (line[length-1] == ' ' || line[length-1] == '\r'
                      || line[length-1] == '\t'))
        length--;
    if (length == 0 || scan == NULL)
        return;

    if (level <= 0) {
        pthread_mutex_lock(&scan->lock);
        snprintf(scan->error_lines[scan->error_line_count % LM_ERROR_LINES],
                 sizeof(scan->error_lines[0]), "%.*s", (int)length, line);
        scan->error_line_count++;
        pthread_mutex_unlock(&scan->lock);
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = LM_EV_LOG;
    ev.level = level;
    ev.text = lm_strndup(line, length);
    ev.text_len = length;
    lm_push(scan, &ev);
}

void
lm_log_text(int level, const char *text)
{
    while (*text) {
        const char *end = strchr(text, '\n');
        size_t length = end ? (size_t)(end - text) : strlen(text);

        lm_log_line(level, text, length);
        text += length;
        if (*text == '\n')
            text++;
    }
}

static void
lm_vlog(int level, const char *prefix, const char *fmt, va_list ap)
{
    char buffer[2048];
    size_t used = 0;

    if (prefix) {
        used = (size_t)snprintf(buffer, sizeof(buffer), "%s", prefix);
        if (used >= sizeof(buffer))
            used = sizeof(buffer) - 1;
    }
    vsnprintf(buffer + used, sizeof(buffer) - used, fmt, ap);
    lm_log_text(level, buffer);
}

void
lm_set_verbosity(int level)
{
    lm_verbosity = level;
}

void
LOG_add_level(int level)
{
    lm_verbosity += level;
}

void
LOG(int level, const char *fmt, ...)
{
    va_list ap;

    if (level > lm_verbosity)
        return;
    va_start(ap, fmt);
    lm_vlog(level, NULL, fmt, ap);
    va_end(ap);
}

void
LOGip(int level, ipaddress ip, unsigned port, const char *fmt, ...)
{
    char prefix[96];
    ipaddress_formatted_t fmt_ip;
    va_list ap;

    if (level > lm_verbosity)
        return;
    fmt_ip = ipaddress_fmt(ip);
    snprintf(prefix, sizeof(prefix), "%-15s:%5u: ", fmt_ip.string, port);
    va_start(ap, fmt);
    lm_vlog(level, prefix, fmt, ap);
    va_end(ap);
}

void
LOGnet(unsigned port_me, ipaddress ip_them, const char *fmt, ...)
{
    char prefix[96];
    ipaddress_formatted_t fmt_ip;
    va_list ap;

    /* Upstream prints these TCP trace lines at every verbosity. */
    if (1 > lm_verbosity)
        return;
    fmt_ip = ipaddress_fmt(ip_them);
    snprintf(prefix, sizeof(prefix), "%u:%s: ", port_me, fmt_ip.string);
    va_start(ap, fmt);
    lm_vlog(1, prefix, fmt, ap);
    va_end(ap);
}

int
libmasscan_vfprintf(FILE *fp, const char *fmt, va_list ap)
{
    char buffer[2048];
    int length;

    if (fp != stderr)
        return vfprintf(fp, fmt, ap);

    length = vsnprintf(buffer, sizeof(buffer), fmt, ap);
    lm_log_text(0, buffer);
    return length;
}

int
libmasscan_fprintf(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    int length;

    va_start(ap, fmt);
    length = libmasscan_vfprintf(fp, fmt, ap);
    va_end(ap);
    return length;
}

int
libmasscan_printf(const char *fmt, ...)
{
    va_list ap;
    int length;

    va_start(ap, fmt);
    length = libmasscan_vfprintf(stderr, fmt, ap);
    va_end(ap);
    return length;
}

void
libmasscan_exit(int code)
{
    jmp_buf *target = lm_exit_jmp;

    /* No scan threads yet: unwind to lm_run(). */
    if (target && !lm_threads_started) {
        lm_exit_code = code;
        lm_exit_jmp = NULL;
        longjmp(*target, 1);
    }

    /* Scan threads use the runner's stack, so unwinding is unsafe. Disable the module. */
    lm_poisoned = 1;
    is_tx_done = 1;
    is_rx_done = 1;
    LOG(0, "FAIL: masscan called exit(%d) while the scan threads ran. "
           "Restart the process before the next scan.\n", code);

    /* No scan receives the log line, so print it. */
    if (lm_current == NULL)
        fprintf(stderr, "libmasscan: masscan called exit(%d) outside a "
                        "scan. Later scans will be refused.\n", code);
#ifdef LM_HAVE_BACKTRACE
    if (getenv("LIBMASSCAN_DEBUG")) {
        void *frames[32];
        int n = backtrace(frames, 32);
        fprintf(stderr, "libmasscan: exit(%d) called from:\n", code);
        backtrace_symbols_fd(frames, n, 2);
    }
#endif

    if (target) {
        struct lm_scan *scan = lm_current;
        struct lm_run_result result;

        memset(&result, 0, sizeof(result));
        result.failed = 1;
        result.exit_code = code;
        if (scan)
            lm_complete(scan, &result);
        /* Keep this stack alive for the scan threads. */
        for (;;)
            pixie_mssleep(1000);
    }

    /* A scan thread. End only this thread. */
    pthread_exit(NULL);
}

void
status_start(struct Status *status)
{
    memset(status, 0, sizeof(*status));
    status->last.clock = (double)pixie_gettime();
    status->last.time = time(0);
}

void
status_finish(struct Status *status)
{
    (void)status;
}

void
status_print(struct Status *status, uint64_t count, uint64_t max_count,
             double rate, uint64_t total_tcbs, uint64_t total_synacks,
             uint64_t total_syns, uint64_t exiting, bool json_status)
{
    struct lm_event ev;
    (void)json_status;

    if (is_rx_done)
        lm_wake_receivers();

    /* UINT64_MAX until the threads report in. */
    if (count == UINT64_MAX)
        count = 0;

    status->last.count = count;
    lm_last_index = count;
    status->total_tcbs = total_tcbs;
    status->total_synacks = total_synacks;
    status->total_syns = total_syns;

    memset(&ev, 0, sizeof(ev));
    ev.type = LM_EV_PROGRESS;
    ev.count = count;
    ev.total = max_count;
    ev.percent = max_count ? (100.0 * (double)count / (double)max_count) : 0;
    if (ev.percent > 100.0)
        ev.percent = 100.0;
    ev.rate = rate;
    ev.syns = total_syns;
    ev.synacks = total_synacks;
    ev.tcbs = total_tcbs;
    ev.remaining = exiting ? (int64_t)exiting : -1;
    if (status->is_infinite)
        ev.percent = -1;
    lm_push(lm_current, &ev);
}

static int
lm_is_file_output(const struct Output *out)
{
    return !(out->is_interactive || out->format == 0
             || out->format == Output_Interactive);
}

void
output_report_status(struct Output *out, time_t timestamp, int status,
                     ipaddress ip, unsigned ip_proto, unsigned port,
                     unsigned reason, unsigned ttl,
                     const unsigned char mac[6])
{
    struct lm_event ev;
    ipaddress_formatted_t fmt_ip;

    global_now = time(0);

    /* Same filters as upstream: --open-only and --show closed. */
    if (!out->is_show_closed && status == PortStatus_Closed)
        return;
    if (!out->is_show_open && status == PortStatus_Open)
        return;

    memset(&ev, 0, sizeof(ev));
    ev.type = LM_EV_RESULT;
    fmt_ip = ipaddress_fmt(ip);
    snprintf(ev.ip, sizeof(ev.ip), "%s", fmt_ip.string);
    ev.port = port;
    ev.ip_proto = ip_proto;
    ev.ttl = ttl;
    ev.status = status;
    ev.timestamp = timestamp;
    if (ip_proto == 6)
        reason_string(reason, ev.reason, sizeof(ev.reason));
    if (ip_proto == 0 && mac)
        snprintf(ev.mac, sizeof(ev.mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    lm_push(lm_current, &ev);

    /* Keep upstream file output (-oJ, -oX, ...). Skip interactive stdout output. */
    if (lm_is_file_output(out))
        lm_orig_output_report_status(out, timestamp, status, ip, ip_proto,
                                     port, reason, ttl, mac);
}

void
output_report_banner(struct Output *out, time_t timestamp, ipaddress ip,
                     unsigned ip_proto, unsigned port, unsigned proto,
                     unsigned ttl, const unsigned char *px, unsigned length)
{
    struct lm_event ev;
    ipaddress_formatted_t fmt_ip;

    /* Same filter as upstream. */
    if (!out->is_banner)
        return;

    memset(&ev, 0, sizeof(ev));
    ev.type = LM_EV_BANNER;
    fmt_ip = ipaddress_fmt(ip);
    snprintf(ev.ip, sizeof(ev.ip), "%s", fmt_ip.string);
    ev.port = port;
    ev.ip_proto = ip_proto;
    ev.ttl = ttl;
    ev.timestamp = timestamp;
    snprintf(ev.service, sizeof(ev.service), "%s",
             masscan_app_to_string((enum ApplicationProtocol)proto));
    ev.text = lm_strndup((const char *)px, length);
    ev.text_len = ev.text ? length : 0;
    lm_push(lm_current, &ev);

    if (lm_is_file_output(out))
        lm_orig_output_report_banner(out, timestamp, ip, ip_proto, port,
                                     proto, ttl, px, length);
}
