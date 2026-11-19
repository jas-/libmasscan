/* Includes upstream main.c to call its static main_scan(). The macros below adapt it to a library. */
#include "shim/libmasscan-shim.h"
#include "libmasscan.h"

#include <dlfcn.h>
#include <signal.h>
#include <setjmp.h>
#include <stddef.h>

static void
lm_ignore_signal(int sig, void (*handler)(int))
{
    (void)sig;
    (void)handler;
}

#define signal(sig, handler) lm_ignore_signal((sig), (handler))
#define main masscan_cli_main
#define masscan_save_state lm_save_state
#define pixie_begin_thread lm_begin_thread
#define masscan_initialize_adapter lm_initialize_adapter

#include "main.c"

#undef signal
#undef main
#undef masscan_save_state
#undef pixie_begin_thread
#undef masscan_initialize_adapter

#include "rawsock-adapter.h"
#include "stub-pfring.h"

size_t pixie_begin_thread(void (*worker_thread)(void*), unsigned flags,
                          void *worker_data);
int masscan_initialize_adapter(struct Masscan *masscan, unsigned index,
                               macaddress_t *source_mac,
                               macaddress_t *router_mac_ipv4,
                               macaddress_t *router_mac_ipv6);

/* Upstream bug: --offline leaves link type 0, and the IPv6 template check fails on Linux. Use Ethernet. */
int
lm_initialize_adapter(struct Masscan *masscan, unsigned index,
                      macaddress_t *source_mac, macaddress_t *router_mac_ipv4,
                      macaddress_t *router_mac_ipv6)
{
    int err = masscan_initialize_adapter(masscan, index, source_mac,
                                         router_mac_ipv4, router_mac_ipv6);
    if (err == 0 && masscan->is_offline && masscan->nic[index].adapter
        && masscan->nic[index].adapter->link_type == 0) {
        masscan->nic[index].adapter->link_type = 1; /* PCAP_DLT_ETHERNET */
        masscan->nic[index].link_type = 1;
    }
    return err;
}

static volatile int lm_has_saved_state;
static volatile uint64_t lm_saved_index;

/* The running scan. Runner thread only. */
static struct Masscan *lm_active;

typedef void (*lm_breakloop_fn)(struct pcap *);

/* Masscan's pcap stub has no pcap_breakloop(). Find it in the already loaded libpcap. */
static lm_breakloop_fn
lm_pcap_breakloop(void)
{
    static const char *names[] = {
        "libpcap.so", "libpcap.A.dylib", "libpcap.dylib", "libpcap.so.1",
        "libpcap.so.0.9.5", "libpcap.so.0.9.4", "libpcap.so.0.8", NULL
    };
    static int resolved = 0;
    static lm_breakloop_fn fn = NULL;
    unsigned i;

    if (resolved)
        return fn;
    resolved = 1;
    for (i = 0; names[i]; i++) {
        void *h = dlopen(names[i], RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            fn = (lm_breakloop_fn)dlsym(h, "pcap_breakloop");
            if (fn)
                break;
        }
    }
    return fn;
}

/* On Linux, pcap_next() can block past the wait window, and main_scan() then calls exit(). */
void
lm_wake_receivers(void)
{
    lm_breakloop_fn breakloop;
    unsigned i;

    if (lm_active == NULL || !is_rx_done)
        return;
    breakloop = lm_pcap_breakloop();
    if (breakloop == NULL)
        return;
    for (i = 0; i < lm_active->nic_count
                && i < sizeof(lm_active->nic) / sizeof(lm_active->nic[0]); i++) {
        struct Adapter *adapter = lm_active->nic[i].adapter;
        if (adapter && adapter->pcap)
            breakloop(adapter->pcap);
    }
}

void
lm_save_state(struct Masscan *masscan)
{
    lm_saved_index = masscan->resume.index;
    lm_has_saved_state = 1;
}

size_t
lm_begin_thread(void (*worker_thread)(void*), unsigned flags,
                void *worker_data)
{
    lm_threads_started = 1;
    return pixie_begin_thread(worker_thread, flags, worker_data);
}

void
lm_reset_globals(void)
{
    is_tx_done = 0;
    is_rx_done = 0;
    lm_threads_started = 0;
    lm_has_saved_state = 0;
    lm_saved_index = 0;
    lm_last_index = 0;
}

/* First call: stop sending. force or a second call: stop receiving too. */
void
lm_request_stop(int force)
{
    if (force || is_tx_done)
        is_rx_done = 1;
    is_tx_done = 1;
}

/* Upstream never closes adapters. Close them so repeat scans do not leak descriptors. */
static void
lm_close_adapters(struct Masscan *masscan)
{
    unsigned i;

    for (i = 0; i < masscan->nic_count && i < sizeof(masscan->nic)
                                              / sizeof(masscan->nic[0]); i++) {
        struct Adapter *adapter = masscan->nic[i].adapter;

        if (adapter == NULL)
            continue;
        if (adapter->ring)
            PFRING.close(adapter->ring);
        if (adapter->pcap)
            PCAP.close(adapter->pcap);
        if (adapter->sendq)
            PCAP.sendqueue_destroy(adapter->sendq);
        free(adapter);
        masscan->nic[i].adapter = NULL;
    }
}

static void
lm_once_init(void)
{
    static int done = 0;

    if (done)
        return;
    done = 1;

    if (pcap_init() != 0)
        LOG(2, "libpcap: failed to load\n");
    rawsock_init();
    snmp_init();
    x509_init();
}

static void
lm_fail(struct lm_run_result *result, const char *message)
{
    result->failed = 1;
    result->exit_code = 1;
    snprintf(result->message, sizeof(result->message), "%s", message);
}

/* Upstream main() for Operation_Scan. Returns 0, or -1 with result->failed set. */
int
lm_run(int argc, char **argv, struct lm_run_result *result)
{
    jmp_buf trap;
    struct Masscan *volatile masscan = NULL;
    int has_target_addresses;
    int has_target_ports;
    int rc;

    memset(result, 0, sizeof(*result));

    masscan = calloc(1, sizeof(*masscan));
    if (masscan == NULL) {
        lm_fail(result, "out of memory");
        return -1;
    }

    if (setjmp(trap)) {
        /* masscan called exit() before any scan thread started. */
        lm_exit_jmp = NULL;
        result->failed = 1;
        result->exit_code = lm_exit_code;
        lm_close_adapters(masscan);
        free(masscan);
        return -1;
    }
    lm_exit_jmp = &trap;

    usec_start = pixie_gettime();
    global_now = time(0);

    /* Defaults, as in upstream main() */
    masscan->blackrock_rounds = 14;
    masscan->output.is_show_open = 1;
    masscan->output.is_status_updates = 1; /* drives status_print() */
    masscan->wait = 10;
    masscan->max_rate = 100.0;
    masscan->nic_count = 1;
    masscan->shard.one = 1;
    masscan->shard.of = 1;
    masscan->min_packet_size = 60;
    masscan->payloads.udp = payloads_udp_create();
    masscan->payloads.oproto = payloads_oproto_create();
    safe_strcpy(masscan->output.rotate.directory,
                sizeof(masscan->output.rotate.directory), ".");
    masscan->is_capture_cert = 1;

    /* Read the system exclude list, as the CLI does. */
    if (!masscan_conf_contains("--readscan", argc, argv)
        && access("/etc/masscan/masscan.conf", 0) == 0)
        masscan_read_config_file(masscan, "/etc/masscan/masscan.conf");

    masscan_command_line(masscan, argc, argv);

    masscan->output.is_status_updates = 1;

    if (masscan->op != Operation_Scan) {
        LOG(0, "FAIL: libmasscan runs scans only. The options selected "
               "another masscan operation (%d).\n", (int)masscan->op);
        lm_fail(result, "the options do not describe a scan");
        goto fail;
    }

    if (masscan->seed == 0)
        masscan->seed = get_entropy();

    masscan_load_database_files(masscan);
    if (masscan->is_scripting)
        scripting_init(masscan);

    lm_once_init();

    has_target_addresses = massip_has_ipv4_targets(&masscan->targets)
                           || massip_has_ipv6_targets(&masscan->targets);
    has_target_ports = massip_has_target_ports(&masscan->targets);
    massip_apply_excludes(&masscan->targets, &masscan->exclude);
    massip_optimize(&masscan->targets);

    if (massint128_bitcount(massip_range(&masscan->targets)) > 63) {
        LOG(0, "FAIL: scan range too large, max is 63-bits, requested is "
               "%u bits\n",
            massint128_bitcount(massip_range(&masscan->targets)));
        lm_fail(result, "scan range too large");
        goto fail;
    }

    if (rangelist_count(&masscan->targets.ipv4) == 0
        && massint128_is_zero(range6list_count(&masscan->targets.ipv6))) {
        if (has_target_addresses)
            LOG(0, "FAIL: all target addresses were removed by exclusion "
                   "ranges\n");
        else
            LOG(0, "FAIL: target IP address list empty\n");
        lm_fail(result, "no target addresses");
        goto fail;
    }
    if (rangelist_count(&masscan->targets.ports) == 0) {
        if (has_target_ports)
            LOG(0, "FAIL: all ports were removed by exclusion ranges\n");
        else
            LOG(0, "FAIL: no ports were specified\n");
        lm_fail(result, "no target ports");
        goto fail;
    }

    lm_active = masscan;
    rc = main_scan(masscan);
    lm_active = NULL;

    lm_exit_jmp = NULL;
    if (rc != 0) {
        result->failed = 1;
        result->exit_code = rc;
    } else if (lm_poisoned) {
        /* A scan thread called exit() and ended, so the results are incomplete. */
        result->failed = 1;
        result->exit_code = 1;
    }
    if (lm_has_saved_state) {
        /* Upstream's saved index can lag the transmit thread. Use the later one. */
        result->has_resume = 1;
        result->resume_index = lm_last_index > lm_saved_index
                                   ? lm_last_index : lm_saved_index;
    }
    lm_close_adapters(masscan);
    free(masscan);
    return rc == 0 ? 0 : -1;

fail:
    lm_exit_jmp = NULL;
    lm_close_adapters(masscan);
    free(masscan);
    return -1;
}
