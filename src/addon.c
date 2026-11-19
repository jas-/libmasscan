/* N-API binding: start(args, onEvents), stop(force), isRunning(). One scan per process. */
#define NAPI_VERSION 8
#include <node_api.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmasscan.h"
#include "masscan-status.h"

static volatile int lm_busy = 0;

#define NAPI_CALL(env, call)                                            \
    do {                                                                \
        if ((call) != napi_ok) {                                        \
            const napi_extended_error_info *info = NULL;                \
            napi_get_last_error_info((env), &info);                     \
            napi_throw_error((env), NULL,                               \
                info && info->error_message ? info->error_message       \
                                            : "N-API call failed");     \
            return NULL;                                                \
        }                                                               \
    } while (0)

static void
scan_free(struct lm_scan *scan)
{
    size_t i;
    int j;

    for (i = 0; i < scan->count; i++)
        free(scan->events[i].text);
    free(scan->events);
    for (j = 0; j < scan->argc; j++)
        free(scan->argv[j]);
    free(scan->argv);
    pthread_mutex_destroy(&scan->lock);
    free(scan);
}

void
lm_notify(struct lm_scan *scan)
{
    napi_call_threadsafe_function((napi_threadsafe_function)scan->tsfn,
                                  NULL, napi_tsfn_nonblocking);
}

static char *
error_text(struct lm_scan *scan, const struct lm_run_result *result)
{
    char buffer[LM_ERROR_LINES * 258 + 300];
    size_t used = 0;
    unsigned first, i;

    pthread_mutex_lock(&scan->lock);
    first = scan->error_line_count > LM_ERROR_LINES
                ? scan->error_line_count - LM_ERROR_LINES : 0;
    for (i = first; i < scan->error_line_count; i++) {
        int n = snprintf(buffer + used, sizeof(buffer) - used, "%s%s",
                         used ? "\n" : "",
                         scan->error_lines[i % LM_ERROR_LINES]);
        if (n < 0 || (size_t)n >= sizeof(buffer) - used)
            break;
        used += (size_t)n;
    }
    pthread_mutex_unlock(&scan->lock);

    if (used == 0) {
        if (result->message[0])
            snprintf(buffer, sizeof(buffer), "%s", result->message);
        else
            snprintf(buffer, sizeof(buffer),
                     "masscan stopped with exit code %d", result->exit_code);
    }
    return strdup(buffer);
}

void
lm_complete(struct lm_scan *scan, const struct lm_run_result *result)
{
    struct lm_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.type = LM_EV_DONE;
    ev.failed = result->failed;
    ev.exit_code = result->exit_code;
    ev.has_resume = result->has_resume;
    ev.resume_index = result->resume_index;
    if (result->failed) {
        ev.text = error_text(scan, result);
        ev.text_len = ev.text ? strlen(ev.text) : 0;
    }

    /* Clear busy before queueing done, so a 'done' handler can start the next scan. */
    lm_current = NULL;
    lm_busy = 0;
    lm_push(scan, &ev);
    napi_release_threadsafe_function((napi_threadsafe_function)scan->tsfn,
                                     napi_tsfn_release);
}

static void *
scan_thread(void *arg)
{
    struct lm_scan *scan = arg;
    struct lm_run_result result;

    lm_run(scan->argc, scan->argv, &result);
    lm_complete(scan, &result);
    return NULL;
}

static const char *
protocol_name(unsigned ip_proto)
{
    switch (ip_proto) {
    case 0:   return "arp";
    case 1:   return "icmp";
    case 6:   return "tcp";
    case 17:  return "udp";
    case 132: return "sctp";
    default:  return NULL;
    }
}

static const char *
status_name(int status)
{
    switch (status) {
    case PortStatus_Open:   return "open";
    case PortStatus_Closed: return "closed";
    case PortStatus_Arp:    return "arp";
    default:                return "unknown";
    }
}

static napi_status
set_string(napi_env env, napi_value obj, const char *key, const char *value)
{
    napi_value v;
    napi_status s = napi_create_string_utf8(env, value, NAPI_AUTO_LENGTH, &v);
    return s == napi_ok ? napi_set_named_property(env, obj, key, v) : s;
}

static napi_status
set_number(napi_env env, napi_value obj, const char *key, double value)
{
    napi_value v;
    napi_status s = napi_create_double(env, value, &v);
    return s == napi_ok ? napi_set_named_property(env, obj, key, v) : s;
}

static napi_status
set_null(napi_env env, napi_value obj, const char *key)
{
    napi_value v;
    napi_get_null(env, &v);
    return napi_set_named_property(env, obj, key, v);
}

static void
set_protocol(napi_env env, napi_value obj, unsigned ip_proto)
{
    const char *name = protocol_name(ip_proto);
    if (name)
        set_string(env, obj, "protocol", name);
    else
        set_number(env, obj, "protocol", ip_proto);
}

static napi_value
event_to_js(napi_env env, const struct lm_event *ev)
{
    napi_value obj, v;

    if (napi_create_object(env, &obj) != napi_ok)
        return NULL;

    switch (ev->type) {
    case LM_EV_RESULT:
        set_string(env, obj, "type", "result");
        set_string(env, obj, "ip", ev->ip);
        set_number(env, obj, "port", ev->port);
        set_protocol(env, obj, ev->ip_proto);
        set_string(env, obj, "status", status_name(ev->status));
        set_number(env, obj, "ttl", ev->ttl);
        if (ev->reason[0])
            set_string(env, obj, "reason", ev->reason);
        if (ev->mac[0])
            set_string(env, obj, "mac", ev->mac);
        set_number(env, obj, "timestamp", (double)ev->timestamp * 1000.0);
        break;

    case LM_EV_BANNER:
        set_string(env, obj, "type", "banner");
        set_string(env, obj, "ip", ev->ip);
        set_number(env, obj, "port", ev->port);
        set_protocol(env, obj, ev->ip_proto);
        set_string(env, obj, "service", ev->service);
        /* latin1 keeps every raw byte. */
        napi_create_string_latin1(env, ev->text ? ev->text : "",
                                  ev->text_len, &v);
        napi_set_named_property(env, obj, "banner", v);
        set_number(env, obj, "ttl", ev->ttl);
        set_number(env, obj, "timestamp", (double)ev->timestamp * 1000.0);
        break;

    case LM_EV_PROGRESS:
        set_string(env, obj, "type", "progress");
        if (ev->percent < 0)
            set_null(env, obj, "percent");
        else
            set_number(env, obj, "percent", ev->percent);
        set_number(env, obj, "rate", ev->rate);
        set_number(env, obj, "sent", (double)ev->syns);
        set_number(env, obj, "synacks", (double)ev->synacks);
        set_number(env, obj, "tcbs", (double)ev->tcbs);
        set_number(env, obj, "index", (double)ev->count);
        set_number(env, obj, "total", (double)ev->total);
        if (ev->remaining < 0)
            set_null(env, obj, "waitRemaining");
        else
            set_number(env, obj, "waitRemaining", (double)ev->remaining);
        break;

    case LM_EV_LOG:
        set_string(env, obj, "type", "log");
        set_number(env, obj, "level", ev->level);
        set_string(env, obj, "message", ev->text ? ev->text : "");
        break;

    case LM_EV_DONE:
        set_string(env, obj, "type", "done");
        if (ev->failed) {
            set_string(env, obj, "error", ev->text ? ev->text : "scan failed");
            set_number(env, obj, "exitCode", ev->exit_code);
        } else {
            set_null(env, obj, "error");
        }
        if (ev->has_resume)
            set_number(env, obj, "resumeIndex", (double)ev->resume_index);
        else
            set_null(env, obj, "resumeIndex");
        break;
    }
    return obj;
}

static void
call_js(napi_env env, napi_value js_callback, void *context, void *data)
{
    struct lm_scan *scan = context;
    struct lm_event *events;
    size_t count, i;
    napi_value array, undefined;
    (void)data;

    pthread_mutex_lock(&scan->lock);
    events = scan->events;
    count = scan->count;
    scan->events = NULL;
    scan->count = 0;
    scan->capacity = 0;
    scan->notify_pending = 0;
    pthread_mutex_unlock(&scan->lock);

    if (env != NULL && js_callback != NULL && count > 0
        && napi_create_array_with_length(env, count, &array) == napi_ok) {
        for (i = 0; i < count; i++) {
            napi_value obj = event_to_js(env, &events[i]);
            if (obj)
                napi_set_element(env, array, (uint32_t)i, obj);
        }
        napi_get_undefined(env, &undefined);
        napi_call_function(env, undefined, js_callback, 1, &array, NULL);
    }

    for (i = 0; i < count; i++)
        free(events[i].text);
    free(events);
}

static void
tsfn_finalize(napi_env env, void *finalize_data, void *hint)
{
    (void)env;
    (void)hint;
    scan_free(finalize_data);
}

static napi_value
Start(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2], resource_name;
    bool is_array;
    uint32_t length, i;
    napi_valuetype type;
    struct lm_scan *scan;
    pthread_attr_t attr;
    pthread_t thread;
    napi_threadsafe_function tsfn;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, NULL, NULL));
    if (argc < 2) {
        napi_throw_type_error(env, NULL, "start(args, onEvents) needs 2 arguments");
        return NULL;
    }
    NAPI_CALL(env, napi_is_array(env, args[0], &is_array));
    NAPI_CALL(env, napi_typeof(env, args[1], &type));
    if (!is_array || type != napi_function) {
        napi_throw_type_error(env, NULL, "start(args, onEvents) needs an array and a function");
        return NULL;
    }
    if (lm_poisoned) {
        napi_throw_error(env, "ERR_MASSCAN_POISONED",
            "An earlier scan failed fatally. Restart the process before the next scan.");
        return NULL;
    }
    if (lm_busy) {
        napi_throw_error(env, "ERR_MASSCAN_BUSY",
            "A scan is already running. Masscan keeps global state, so a "
            "process runs one scan at a time.");
        return NULL;
    }

    scan = calloc(1, sizeof(*scan));
    if (scan == NULL) {
        napi_throw_error(env, NULL, "out of memory");
        return NULL;
    }
    pthread_mutex_init(&scan->lock, NULL);

    NAPI_CALL(env, napi_get_array_length(env, args[0], &length));
    scan->argv = calloc((size_t)length + 2, sizeof(char *));
    if (scan->argv == NULL) {
        scan_free(scan);
        napi_throw_error(env, NULL, "out of memory");
        return NULL;
    }
    scan->argv[scan->argc++] = strdup("masscan");
    for (i = 0; i < length; i++) {
        napi_value item;
        size_t size;

        if (napi_get_element(env, args[0], i, &item) != napi_ok
            || napi_typeof(env, item, &type) != napi_ok
            || type != napi_string) {
            scan_free(scan);
            napi_throw_type_error(env, NULL, "every argument must be a string");
            return NULL;
        }
        napi_get_value_string_utf8(env, item, NULL, 0, &size);
        scan->argv[scan->argc] = malloc(size + 1);
        if (scan->argv[scan->argc] == NULL) {
            scan_free(scan);
            napi_throw_error(env, NULL, "out of memory");
            return NULL;
        }
        napi_get_value_string_utf8(env, item, scan->argv[scan->argc],
                                   size + 1, &size);
        scan->argc++;
    }

    NAPI_CALL(env, napi_create_string_utf8(env, "masscan", NAPI_AUTO_LENGTH,
                                           &resource_name));
    if (napi_create_threadsafe_function(env, args[1], NULL, resource_name,
            0, 1, scan, tsfn_finalize, scan, call_js, &tsfn) != napi_ok) {
        scan_free(scan);
        napi_throw_error(env, NULL, "cannot create the event channel");
        return NULL;
    }
    scan->tsfn = tsfn;

    lm_reset_globals();
    lm_set_verbosity(0);
    lm_busy = 1;
    lm_current = scan;

    /* main_scan() needs more stack than the macOS default of 512 KB. */
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 16 * 1024 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&thread, &attr, scan_thread, scan) != 0) {
        pthread_attr_destroy(&attr);
        lm_current = NULL;
        lm_busy = 0;
        /* Releasing the last reference calls tsfn_finalize. */
        napi_release_threadsafe_function(tsfn, napi_tsfn_abort);
        napi_throw_error(env, NULL, "cannot start the scan thread");
        return NULL;
    }
    pthread_attr_destroy(&attr);
    return NULL;
}

static napi_value
Stop(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value arg;
    bool force = false;
    napi_valuetype type;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, &arg, NULL, NULL));
    if (argc >= 1 && napi_typeof(env, arg, &type) == napi_ok
        && type == napi_boolean)
        napi_get_value_bool(env, arg, &force);

    if (lm_busy)
        lm_request_stop(force ? 1 : 0);
    return NULL;
}

static napi_value
IsRunning(napi_env env, napi_callback_info info)
{
    napi_value result;
    (void)info;
    napi_get_boolean(env, lm_busy != 0, &result);
    return result;
}

static napi_value
Init(napi_env env, napi_value exports)
{
    napi_property_descriptor props[] = {
        { "start", NULL, Start, NULL, NULL, NULL, napi_default, NULL },
        { "stop", NULL, Stop, NULL, NULL, NULL, napi_default, NULL },
        { "isRunning", NULL, IsRunning, NULL, NULL, NULL, napi_default, NULL },
    };
    NAPI_CALL(env, napi_define_properties(env, exports,
                                          sizeof(props) / sizeof(props[0]),
                                          props));
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
