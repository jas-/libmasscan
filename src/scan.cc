#define __STDC_LIMIT_MACROS

#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

extern "C" {
  #include "masscan/src/masscan.h"
  #include "masscan/src/masscan-version.h"
  #include "masscan/src/masscan-status.h"     /* open or closed */
  #include "masscan/src/rand-blackrock.h"     /* the BlackRock shuffling func */
  #include "masscan/src/rand-lcg.h"           /* the LCG randomization func */
  #include "masscan/src/templ-pkt.h"          /* packet template, that we use to send */
  #include "masscan/src/rawsock.h"            /* api on top of Linux, Windows, Mac OS X*/
  #include "masscan/src/logger.h"             /* adjust with -v command-line opt */
  #include "masscan/src/main-status.h"        /* printf() regular status updates */
  #include "masscan/src/main-throttle.h"      /* rate limit */
  #include "masscan/src/main-dedup.h"         /* ignore duplicate responses */
  #include "masscan/src/main-ptrace.h"        /* for nmap --packet-trace feature */
  #include "masscan/src/proto-arp.h"          /* for responding to ARP requests */
  #include "masscan/src/proto-banner1.h"      /* for snatching banners from systems */
  #include "masscan/src/proto-tcp.h"          /* for TCP/IP connection table */
  #include "masscan/src/proto-preprocess.h"   /* quick parse of packets */
  #include "masscan/src/proto-icmp.h"         /* handle ICMP responses */
  #include "masscan/src/proto-udp.h"          /* handle UDP responses */
  #include "masscan/src/syn-cookie.h"         /* for SYN-cookies on send */
  #include "masscan/src/output.h"             /* for outputing results */
  #include "masscan/src/rte-ring.h"           /* producer/consumer ring buffer */
  #include "masscan/src/rawsock.h"
  #include "masscan/src/rawsock-pcapfile.h"   /* for saving pcap files w/ raw packets */
  #include "masscan/src/smack.h"              /* Aho-corasick state-machine pattern-matcher */
  #include "masscan/src/pixie-timer.h"        /* portable time functions */
  #include "masscan/src/pixie-threads.h"      /* portable threads */
  #include "masscan/src/templ-payloads.h"     /* UDP packet payloads */
  #include "masscan/src/proto-snmp.h"         /* parse SNMP responses */
  #include "masscan/src/proto-ntp.h"          /* parse NTP responses */
  #include "masscan/src/templ-port.h"
  #include "masscan/src/in-binary.h"          /* covert binary output to XML/JSON */
  #include "masscan/src/main-globals.h"       /* all the global variables in the program */
  #include "masscan/src/proto-zeroaccess.h"
  #include "masscan/src/siphash24.h"
  #include "masscan/src/proto-x509.h"
  #include "masscan/src/crypto-base64.h"      /* base64 encode/decode */
  #include "masscan/src/pixie-backtrace.h"
  #include "masscan/src/proto-sctp.h"
  #include "masscan/src/script.h"
  #include "masscan/src/main-readrange.h"

  #include <assert.h>
  #include <limits.h>
  #include <string.h>
  #include <time.h>
  #include <stdlib.h>
  #include <signal.h>

  #include <stdint.h>

  #if defined(WIN32)
  #include <WinSock.h>
  #if defined(_MSC_VER)
  #pragma comment(lib, "Ws2_32.lib")
  #endif
  #else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #endif

  #include "./output.h"

  unsigned control_c_pressed = 0;
  static unsigned control_c_pressed_again = 0;
  time_t global_now;

  struct ThreadPair {
    const struct Masscan *masscan;
    struct Adapter *adapter;

    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;

    unsigned nic_index;
    unsigned *picker;

    volatile uint64_t my_index;

    struct TemplateSet tmplset[1];
    struct Source src;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];

    unsigned done_transmitting;
    unsigned done_receiving;

    double pt_start;

    struct Throttler throttler[1];

    uint64_t *total_synacks;
    uint64_t *total_tcbs;
    uint64_t *total_syns;
  };

  static void get_sources(const struct Masscan *masscan, unsigned nic_index,
                          unsigned *src_ip, unsigned *src_ip_mask,
                          unsigned *src_port, unsigned *src_port_mask) {
    const struct Source *src = &masscan->nic[nic_index].src;

    *src_ip = src->ip.first;
    *src_ip_mask = src->ip.last - src->ip.first;

    *src_port = src->port.first;
    *src_port_mask = src->port.last - src->port.first;
  }

  static void
  flush_packets(struct Adapter *adapter, PACKET_QUEUE *packet_buffers,
                PACKET_QUEUE *transmit_queue, uint64_t *packets_sent,
                uint64_t *batchsize) {
    /*
     * Send a batch of queued packets
     */
    for ( ; (*batchsize); (*batchsize)--) {
        int err;
        struct PacketBuffer *p;

        /*
         * Get the next packet from the transmit queue. This packet was
         * put there by a receive thread, and will contain things like
         * an ACK or an HTTP request
         */
        err = rte_ring_sc_dequeue(transmit_queue, (void**)&p);
        if (err) {
            break; /* queue is empty, nothing to send */
        }


        /*
         * Actually send the packet
         */
        rawsock_send_packet(adapter, p->px, (unsigned)p->length, 1);

        /*
         * Now that we are done with the packet, put it on the free list
         * of buffers that the transmit thread can reuse
         */
        for (err=1; err; ) {
            err = rte_ring_sp_enqueue(packet_buffers, p);
            if (err) {
                LOG(0, "transmit queue full (should be impossible)\n");
                pixie_usleep(10000);
            }
        }


        /*
         * Remember that we sent a packet, which will be used in
         * throttling.
         */
        (*packets_sent)++;
    }

  }

  static unsigned is_nic_port(const struct Masscan *masscan, unsigned ip) {
    unsigned i;
    for (i=0; i<masscan->nic_count; i++)
        if (is_my_port(&masscan->nic[i].src, ip))
            return 1;
    return 0;
  }

  static void receive_thread(void *v) {
    struct ThreadPair *parms = (struct ThreadPair *)v;
    const struct Masscan *masscan = parms->masscan;
    struct Adapter *adapter = parms->adapter;
    int data_link = rawsock_datalink(adapter);
    struct Output *out;
    struct DedupTable *dedup;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;
    uint64_t *status_synack_count;
    uint64_t *status_tcb_count;
    uint64_t entropy = masscan->seed;

    /* some status variables */
    status_synack_count = (uint64_t*)malloc(sizeof(uint64_t));
    *status_synack_count = 0;
    parms->total_synacks = status_synack_count;

    status_tcb_count = (uint64_t*)malloc(sizeof(uint64_t));
    *status_tcb_count = 0;
    parms->total_tcbs = status_tcb_count;

    LOG(0, "recv: start receive thread #%u\n", parms->nic_index);

    /* Lock this thread to a CPU. Transmit threads are on even CPUs,
     * receive threads on odd CPUs */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = parms->nic_index * 2 + 1;
        while (cpu >= cpu_count) {
            cpu -= cpu_count;
            cpu++;
        }
        //TODO:
        //pixie_cpu_set_affinity(cpu);
    }

    /*
     * If configured, open a --pcap file for saving raw packets. This is
     * so that we can debug scans, but also so that we can look at the
     * strange things people send us. Note that we don't record transmitted
     * packets, just the packets we've received.
     */
    if (masscan->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);
    }

    /*
     * Open output. This is where results are reported when saving
     * the --output-format to the --output-filename
     */
    out = output_create(masscan, parms->nic_index);

    /*
     * Create deduplication table. This is so when somebody sends us
     * multiple responses, we only record the first one.
     */
    dedup = dedup_create();

    /*
     * Create a TCP connection table for interacting with live
     * connections when doing --banners
     */
    if (masscan->is_banners) {
        struct TcpCfgPayloads *pay;

        tcpcon = tcpcon_create_table(
            (size_t)((masscan->max_rate/5) / masscan->nic_count),
            parms->transmit_queue,
            parms->packet_buffers,
            &parms->tmplset->pkts[Proto_TCP],
            output_report_banner,
            out,
            masscan->tcb.timeout,
            masscan->seed
            );
        tcpcon_set_banner_flags(tcpcon,
                masscan->is_capture_cert,
                masscan->is_capture_html,
                masscan->is_capture_heartbleed);
        if (masscan->http_user_agent_length)
            tcpcon_set_parameter(   tcpcon,
                                    "http-user-agent",
                                    masscan->http_user_agent_length,
                                    masscan->http_user_agent);
        if (masscan->is_heartbleed)
            tcpcon_set_parameter(   tcpcon,
                                    "heartbleed",
                                    1,
                                    "1");
        if (masscan->tcp_connection_timeout) {
            char foo[64];
            sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "timeout",
                                 strlen(foo),
                                 foo);
        }
        if (masscan->tcp_hello_timeout) {
            char foo[64];
            sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "hello-timeout",
                                 strlen(foo),
                                 foo);
        }

        for (pay = masscan->tcp_payloads; pay; pay = pay->next) {
            char name[64];
            sprintf_s(name, sizeof(name), "hello-string[%u]", pay->port);
            tcpcon_set_parameter(   tcpcon,
                                    name,
                                    strlen(pay->payload_base64),
                                    pay->payload_base64);
        }

    }

    /*
     * In "offline" mode, we don't have any receive threads, so simply
     * wait until transmitter thread is done then go to the end
     */
    if (masscan->is_offline) {
        while (!control_c_pressed_again)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        goto end;
    }

    /*
     * Receive packets. This is where we catch any responses and print
     * them to the terminal.
     */
    LOG(0, "begin receive thread\n");
    while (!control_c_pressed_again) {
        int status;
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;
        unsigned x;
        struct PreprocessedInfo parsed;
        unsigned ip_me;
        unsigned port_me;
        unsigned ip_them;
        unsigned port_them;
        unsigned seqno_me;
        unsigned seqno_them;
        unsigned cookie;

        /*
         * RECEIVE
         *
         * This is the boring part of actually receiving a packet
         */
        err = rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);

        if (err != 0) {
            if (tcpcon)
                tcpcon_timeouts(tcpcon, (unsigned)time(0), 0);
            continue;
        }


        /*
         * Do any TCP event timeouts based on the current timestamp from
         * the packet. For example, if the connection has been open for
         * around 10 seconds, we'll close the connection. (--banners)
         */
        if (tcpcon) {
            tcpcon_timeouts(tcpcon, secs, usecs);
        }

        if (length > 1514)
            continue;

        /*
         * "Preprocess" the response packet. This means to go through and
         * figure out where the TCP/IP headers are and the locations of
         * some fields, like IP address and port numbers.
         */
        x = preprocess_frame(px, length, data_link, &parsed);
        if (!x)
            continue; /* corrupt packet */
        ip_me = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        ip_them = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
        port_me = parsed.port_dst;
        port_them = parsed.port_src;
        seqno_them = TCP_SEQNO(px, parsed.transport_offset);
        seqno_me = TCP_ACKNO(px, parsed.transport_offset);


        switch (parsed.ip_protocol) {
        case 132: /* SCTP */
            cookie = syn_cookie(ip_them, port_them | (Proto_SCTP<<16), ip_me, port_me, entropy) & 0xFFFFFFFF;
            break;
        default:
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF;
        }

        /* verify: my IP address */
        if (!is_my_ip(&parms->src, ip_me))
            continue;
//printf("0x%08x 0x%08x 0x%04x 0x%08x 0x%04x    \n", cookie, ip_them, port_them, ip_me, port_me);


        /*
         * Handle non-TCP protocols
         */
        switch (parsed.found) {
            case FOUND_ARP:
                LOGip(2, ip_them, 0, "-> ARP [%u] \n", px[parsed.found_offset]);
                switch (px[parsed.found_offset + 6]<<8 | px[parsed.found_offset+7]) {
                case 1: /* request */
                    /* This function will transmit a "reply" to somebody's ARP request
                     * for our IP address (as part of our user-mode TCP/IP).
                     * Since we completely bypass the TCP/IP stack, we  have to handle ARPs
                     * ourself, or the router will lose track of us.*/
                    arp_response(   ip_me,
                                    parms->adapter_mac,
                                    px, length,
                                    parms->packet_buffers,
                                    parms->transmit_queue);
                    break;
                case 2: /* response */
                    /* This is for "arp scan" mode, where we are ARPing targets rather
                     * than port scanning them */

                    /* If we aren't doing an ARP scan, then ignore ARP responses */
                    if (!masscan->is_arp)
                        break;

                    /* If this response isn't in our range, then ignore it */
                    if (!rangelist_is_contains(&masscan->targets, ip_them))
                        break;

                    /* Ignore duplicates */
                    if (dedup_is_duplicate(dedup, ip_them, 0, ip_me, 0))
                        continue;

                    /* ...everything good, so now report this response */
                    handle_arp(out, secs, px, length, &parsed);
                    break;
                }
                continue;
            case FOUND_UDP:
            case FOUND_DNS:
                if (!is_nic_port(masscan, port_me))
                    continue;
                if (parms->masscan->nmap.packet_trace)
                    packet_trace(stdout, parms->pt_start, px, length, 0);
                handle_udp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_ICMP:
                handle_icmp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_SCTP:
                handle_sctp(out, secs, px, length, cookie, &parsed, entropy);
                break;
            case FOUND_TCP:
                /* fall down to below */
                break;
            default:
                continue;
        }


        /* verify: my port number */
        if (!is_my_port(&parms->src, port_me))
            continue;
        if (parms->masscan->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start, px, length, 0);

        /* Save raw packet in --pcap file */
        if (pcapfile) {
            pcapfile_writeframe(
                pcapfile,
                px,
                length,
                length,
                secs,
                usecs);
        }

        {
            char buf[64];
            LOGip(5, ip_them, port_them, "-> TCP ackno=0x%08x flags=0x%02x(%s)\n",
                seqno_me,
                TCP_FLAGS(px, parsed.transport_offset),
                reason_string(TCP_FLAGS(px, parsed.transport_offset), buf, sizeof(buf)));
        }

        /* If recording --banners, create a new "TCP Control Block (TCB)" */
        if (tcpcon) {
            struct TCP_Control_Block *tcb;

            /* does a TCB already exist for this connection? */
            tcb = tcpcon_lookup_tcb(tcpcon,
                            ip_me, ip_them,
                            port_me, port_them);

            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (cookie != seqno_me - 1) {
                    LOG(2, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n",
                        (ip_them>>24)&0xff, (ip_them>>16)&0xff, (ip_them>>8)&0xff, (ip_them>>0)&0xff,
                        seqno_me-1, cookie);
                    continue;
                }

                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them,
                                    port_me, port_them,
                                    seqno_me, seqno_them+1,
                                    parsed.ip_ttl);
                    (*status_tcb_count)++;
                }

                tcpcon_handle(tcpcon, tcb, TCP_WHAT_SYNACK,
                    0, 0, secs, usecs, seqno_them+1);

            } else if (tcb) {
                /* If this is an ACK, then handle that first */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_ACK,
                        0, seqno_me, secs, usecs, seqno_them);
                }

                /* If this contains payload, handle that */
                if (parsed.app_length) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_DATA,
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs, seqno_them);
                }

                /* If this is a FIN, handle that. Note that ACK +
                 * payload + FIN can come together */
                if (TCP_IS_FIN(px, parsed.transport_offset)
                    && !TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_FIN,
                        0, parsed.app_length, secs, usecs, seqno_them);
                }

                /* If this is a RST, then we'll be closing the connection */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_RST,
                        0, 0, secs, usecs, seqno_them);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                /*
                 * NO TCB!
                 *  This happens when we've sent a FIN, deleted our connection,
                 *  but the other side didn't get the packet.
                 */
                if (!TCP_IS_RST(px, parsed.transport_offset))
                tcpcon_send_FIN(
                    tcpcon,
                    ip_me, ip_them,
                    port_me, port_them,
                    seqno_them, seqno_me);
            }

        }

        if (TCP_IS_SYNACK(px, parsed.transport_offset)
            || TCP_IS_RST(px, parsed.transport_offset)) {
            /* figure out the status */
            status = PortStatus_Unknown;
            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                status = PortStatus_Open;
            if (TCP_IS_RST(px, parsed.transport_offset)) {
                status = PortStatus_Closed;
            }

            /* verify: syn-cookies */
            if (cookie != seqno_me - 1) {
                LOG(0, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n",
                    (ip_them>>24)&0xff, (ip_them>>16)&0xff,
                    (ip_them>>8)&0xff, (ip_them>>0)&0xff,
                    seqno_me-1, cookie);
                continue;
            }

            /* verify: ignore duplicates */
            if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me))
                continue;

            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                (*status_synack_count)++;

            /*
             * This is where we do the output
             */
            output_report_status(
                        out,
                        global_now,
                        status,
                        ip_them,
                        6, /* ip proto = tcp */
                        port_them,
                        px[parsed.transport_offset + 13], /* tcp flags */
                        parsed.ip_ttl
                        );

//enum ApplicationProtocol proto, const unsigned char *px, unsigned length
            ReturnObject(masscan, ip_them, 6 /* ip proto = tcp */, port_them,
                         status, parsed.ip_ttl);

            /*
             * Send RST so other side isn't left hanging (only doing this in
             * complete stateless mode where we aren't tracking banners)
             */
            if (tcpcon == NULL)
                tcp_send_RST(
                    &parms->tmplset->pkts[Proto_TCP],
                    parms->packet_buffers,
                    parms->transmit_queue,
                    ip_them, ip_me,
                    port_them, port_me,
                    0, seqno_me);

        }
    }


    LOG(0, "recv: end receive thread #%u\n", parms->nic_index);

    /*
     * cleanup
     */
end:
    if (tcpcon)
        tcpcon_destroy_table(tcpcon);
    dedup_destroy(dedup);
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    for (;;) {
        void *p;
        int err;
        err = rte_ring_sc_dequeue(parms->packet_buffers, (void**)&p);
        if (err == 0)
            free(p);
        else
            break;
    }

    /* Thread is about to exit */
    parms->done_receiving = 1;

  }

  static void transmit_thread(void *v) /*aka. scanning_thread() */ {
    struct ThreadPair *parms = (struct ThreadPair *)v;
    uint64_t i;
    uint64_t start;
    uint64_t end;
    const struct Masscan *masscan = parms->masscan;
    unsigned retries = masscan->retries;
    unsigned rate = (unsigned)masscan->max_rate;
    unsigned r = retries + 1;
    uint64_t range;
    struct BlackRock blackrock;
    uint64_t count_ips = rangelist_count(&masscan->targets);
    struct Throttler *throttler = parms->throttler;
    struct TemplateSet pkt_template = templ_copy(parms->tmplset);
    unsigned *picker = parms->picker;
    struct Adapter *adapter = parms->adapter;
    uint64_t packets_sent = 0;
    unsigned increment = (masscan->shard.of-1) + masscan->nic_count;
    unsigned src_ip;
    unsigned src_ip_mask;
    unsigned src_port;
    unsigned src_port_mask;
    uint64_t seed = masscan->seed;
    uint64_t repeats = 0; /* --infinite repeats */
    uint64_t *status_syn_count;
    uint64_t entropy = masscan->seed;

    LOG(0, "xmit: starting transmit thread #%u\n", parms->nic_index);

    /* export a pointer to this variable outside this threads so
     * that the 'status' system can print the rate of syns we are
     * sending */
    status_syn_count = (uint64_t*)malloc(sizeof(uint64_t));
    *status_syn_count = 0;
    parms->total_syns = status_syn_count;


    /* Normally, we have just one source address. In special cases, though
     * we can have multiple. */
    get_sources(masscan, parms->nic_index,
                &src_ip, &src_ip_mask,
                &src_port, &src_port_mask);


    /* "THROTTLER" rate-limits how fast we transmit, set with the
     * --max-rate parameter */
    throttler_start(throttler, masscan->max_rate/masscan->nic_count);

  infinite:

    /* Create the shuffler/randomizer. This creates the 'range' variable,
     * which is simply the number of IP addresses times the number of
     * ports */
    range = rangelist_count(&masscan->targets)
            * rangelist_count(&masscan->ports);
    blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

    /* Calculate the 'start' and 'end' of a scan. One reason to do this is
     * to support --shard, so that multiple machines can co-operate on
     * the same scan. Another reason to do this is so that we can bleed
     * a little bit past the end when we have --retries. Yet another
     * thing to do here is deal with multiple network adapters, which
     * is essentially the same logic as shards. */
    start = masscan->resume.index + (masscan->shard.one-1) + parms->nic_index;
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += retries * rate;


    /* -----------------
     * the main loop
     * -----------------*/
    LOG(0, "xmit: starting main loop: [%llu..%llu]\n", start, end);
    for (i=start; i<end; ) {
        uint64_t batch_size;

        /*
         * Do a batch of many packets at a time. That because per-packet
         * throttling is expensive at 10-million pps, so we reduce the
         * per-packet cost by doing batches. At slower rates, the batch
         * size will always be one. (--max-rate)
         */
        batch_size = throttler_next_batch(throttler, packets_sent);

        /*
         * Transmit packets from other thread, when doing --banners. This
         * takes priority over sending SYN packets. If there is so much
         * activity grabbing banners that we cannot transmit more SYN packets,
         * then "batch_size" will get decremented to zero, and we won't be
         * able to transmit SYN packets.
         */
        flush_packets(adapter, parms->packet_buffers, parms->transmit_queue,
                        &packets_sent, &batch_size);


        /*
         * Transmit a bunch of packets. At any rate slower than 100,000
         * packets/second, the 'batch_size' is likely to be 1
         */
        while (batch_size && i < end) {
            uint64_t xXx;
            unsigned ip_them;
            unsigned port_them;
            unsigned ip_me;
            unsigned port_me;
            uint64_t cookie;


            /*
             * RANDOMIZE THE TARGET:
             *  This is kinda a tricky bit that picks a random IP and port
             *  number in order to scan. We monotonically increment the
             *  index 'i' from [0..range]. We then shuffle (randomly transmog)
             *  that index into some other, but unique/1-to-1, number in the
             *  same range. That way we visit all targets, but in a random
             *  order. Then, once we've shuffled the index, we "pick" the
             *  IP address and port that the index refers to.
             */
            xXx = (i + (r--) * rate);
            if (rate > range)
                xXx %= range;
            else
                while (xXx >= range)
                    xXx -= range;
            xXx = blackrock_shuffle(&blackrock,  xXx);


            const struct RangeList *fix = &masscan->targets;
            if (fix->count < 1 || fix->count > 1) {
              break;
            }

            ip_them = rangelist_pick2(&masscan->targets, xXx % count_ips, picker);
            port_them = rangelist_pick(&masscan->ports, xXx / count_ips);
            /*
             * SYN-COOKIE LOGIC
             *  Figure out the source IP/port, and the SYN cookie
             */
            if (src_ip_mask > 1 || src_port_mask > 1) {
                uint64_t ck = syn_cookie((unsigned)(i+repeats),
                                        (unsigned)((i+repeats)>>32),
                                        (unsigned)xXx, (unsigned)(xXx>>32),
                                        entropy);
                port_me = src_port + (ck & src_port_mask);
                ip_me = src_ip + ((ck>>16) & src_ip_mask);
            } else {
                ip_me = src_ip;
                port_me = src_port;
            }
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy);
//printf("0x%08x 0x%08x 0x%04x 0x%08x 0x%04x    \n", cookie, ip_them, port_them, ip_me, port_me);
            /*
             * SEND THE PROBE
             *  This is sorta the entire point of the program, but little
             *  exciting happens here. The thing to note that this may
             *  be a "raw" transmit that bypasses the kernel, meaning
             *  we can call this function millions of times a second.
             */
            rawsock_send_probe(
                    adapter,
                    ip_them, port_them,
                    ip_me, port_me,
                    (unsigned)cookie,
                    !batch_size, /* flush queue on last packet in batch */
                    &pkt_template
                    );
            batch_size--;
            packets_sent++;
            (*status_syn_count)++;

            /*
             * SEQUENTIALLY INCREMENT THROUGH THE RANGE
             *  Yea, I know this is a puny 'i++' here, but it's a core feature
             *  of the system that is linearly increments through the range,
             *  but produces from that a shuffled sequence of targets (as
             *  described above). Because we are linearly incrementing this
             *  number, we can do lots of creative stuff, like doing clever
             *  retransmits and sharding.
             */
            if (r == 0) {
                i += increment; /* <------ increment by 1 normally, more with shards/nics */
                r = retries + 1;
            }

        } /* end of batch */


        /* save our current location for resuming, if the user pressed
         * <ctrl-c> to exit early */
        parms->my_index = i;

        /* If the user pressed <ctrl-c>, then we need to exit. but, in case
         * the user wants to --resume the scan later, we save the current
         * state in a file */
        if (control_c_pressed) {
            break;
        }
    }

    /*
     * --infinite
     *  For load testing, go around and do this again
     */
    if (masscan->is_infinite && !control_c_pressed) {
        seed++;
        repeats++;
        goto infinite;
    }

    /*
     * Flush any untransmitted packets. High-speed mechanisms like Windows
     * "sendq" and Linux's "PF_RING" queue packets and transmit many together,
     * so there may be some packets that we've queueud but not yet transmitted.
     * This call makes sure they are transmitted.
     */
    rawsock_flush(adapter);

    /*
     * Wait until the receive thread realizes the scan is over
     */
    LOG(0, "Transmit thread done, waiting for receive thread to realize this\n");
    while (!control_c_pressed)
        pixie_usleep(1000);

    /*
     * We are done transmitting. However, response packets will take several
     * seconds to arrive. Therefore, sit in short loop waiting for those
     * packets to arrive. Pressing <ctrl-c> a second time will exit this
     * prematurely.
     */
    while (!control_c_pressed_again) {
        unsigned k;
        uint64_t batch_size;

        for (k=0; k<1000; k++) {
            /*
             * Only send a few packets at a time, throttled according to the max
             * --max-rate set by the user
             */
            batch_size = throttler_next_batch(throttler, packets_sent);


            /* Transmit packets from the receive thread */
            flush_packets(  adapter,
                            parms->packet_buffers,
                            parms->transmit_queue,
                            &packets_sent,
                            &batch_size);

            /* Make sure they've actually been transmitted, not just queued up for
             * transmit */
            rawsock_flush(adapter);

            pixie_usleep(100);
        }
    }

    /* Thread is about to exit */
    parms->done_transmitting = 1;
    LOG(0, "xmit: stopping transmit thread #%u\n", parms->nic_index);
  }
}

using namespace node;
using namespace v8;

Handle<Value> libmasscan::Scan(struct Masscan *masscan) {
  HandleScope scope;

  struct ThreadPair parms_array[8];
  uint64_t count_ips;
  uint64_t count_ports;
  uint64_t range;
  unsigned index;
  unsigned *picker;
  time_t now = time(0);
  struct Status status;
  uint64_t min_index = UINT64_MAX;
  struct MassScript *script = NULL;

  memset(parms_array, 0, sizeof(parms_array));

  count_ips = rangelist_count(&masscan->targets);
  if (count_ips == 0) {
    LOG(0, "rangelist_count() targets");
    exit(1);
    /* return error of missing targets to callback */
  }

  count_ports = rangelist_count(&masscan->ports);
  if (count_ports == 0) {
    LOG(0, "rangelist_count() ports");
    exit(1);
    /* return error of missing ports to callback */
  }
  range = count_ips * count_ports + (uint64_t)(masscan->retries * masscan->max_rate);


  if (rangelist_is_contains(&masscan->ports, Templ_ARP)) {
    if (masscan->ports.count != 1) {
      LOG(0, "masscan->ports.count > 1 for ARP scan type");
      exit(1);
      /* return error or ARP scan when using ports */
    }
  }

  if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude_ip) == 0) {
    LOG(0, "include an exclude range");
    exit(1);
    /* return error of target range size and include an exclude range */
  }

  payloads_trim(masscan->payloads, &masscan->ports);
  picker = rangelist_pick2_create(&masscan->targets);

  for (index=0; index<masscan->nic_count; index++) {
    struct ThreadPair *parms = &parms_array[index];
    int err;

    parms->masscan = masscan;
    parms->nic_index = index;
    parms->picker = picker;
    parms->my_index = masscan->resume.index;
    parms->done_transmitting = 0;
    parms->done_receiving = 0;

    err = masscan_initialize_adapter(masscan, index, parms->adapter_mac,
                                     parms->router_mac);
    if (err != 0) {
      LOG(0, "masscan_initialize_adapter");
      exit(1);
      /* return error of network adapter init to callback */
    }

    parms->adapter = masscan->nic[index].adapter;
    if (masscan->nic[index].src.ip.range == 0) {
      LOG(0, "masscan->nic[index].src.ip.range = 0");
      exit(1);
      /* return error or IP address per adapter to callback */
    }

    parms->tmplset->script = script;
    template_packet_init(parms->tmplset, parms->adapter_mac, parms->router_mac,
                         masscan->payloads,
                         rawsock_datalink(masscan->nic[index].adapter),
                         masscan->seed);

    if (masscan->nic[index].src.port.range == 0) {
      unsigned port = 40000 + now % 20000;
      masscan->nic[index].src.port.first = port;
      masscan->nic[index].src.port.last = port;
      masscan->nic[index].src.port.range = 1;
    }

    parms->src = masscan->nic[index].src;

    if (masscan->nmap.ttl)
      template_set_ttl(parms->tmplset, masscan->nmap.ttl);

    if (masscan->nic[0].is_vlan)
      template_set_vlan(parms->tmplset, masscan->nic[0].vlan_id);

#define BUFFER_COUNT 16384
    parms->packet_buffers = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
    parms->transmit_queue = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
    {
      unsigned i;
      for (i=0; i<BUFFER_COUNT-1; i++) {
        struct PacketBuffer *p;

        p = (struct PacketBuffer *)malloc(sizeof(*p));
        if (p == NULL) {
          LOG(0, "malloc PacketBuffer");
          exit(1);
          /* return error about memory allocation to call back */
        }

        err = rte_ring_sp_enqueue(parms->packet_buffers, p);
        if (err) {
          /* I dunno why but I can't queue all 256 packets, just 255 */
          LOG(0, "rte_ring_sp_enqueue");
          exit(1);
          /* Ignored */
        }
      }
    }

    pixie_begin_thread(transmit_thread, 0, parms);
    pixie_begin_thread(receive_thread, 0, parms);

    {
      char buffer[80];
      struct tm x;

      now = time(0);
      gmtime_s(&x, &now);
      strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
/*
      LOG(0, "\nStarting masscan " MASSCAN_VERSION " (http://bit.ly/14GZzcT) at %s\n", buffer);
      LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
      LOG(0, "Initiating SYN Stealth Scan\n");
      LOG(0, "Scanning %u hosts [%u port%s/host]\n",
        (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
*/
    }

    status_start(&status);
    status.is_infinite = masscan->is_infinite;
    while (!control_c_pressed) {
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }

        if (min_index >= range && !masscan->is_infinite) {
            /* Note: This is how we can tell the scan has ended */
            control_c_pressed = 1;
        }

        /*
         * update screen about once per second with statistics,
         * namely packets/second.
         */
        status_print(&status, min_index, range, rate,
            total_tcbs, total_synacks, total_syns,
            0);

        /* Sleep for almost a second */
        pixie_mssleep(750);
    }

    /*
     * If we haven't completed the scan, then save the resume
     * information.
     */
    if (min_index < count_ips * count_ports) {
        masscan->resume.index = min_index;

        /* Write current settings to "paused.conf" so that the scan can be restarted */
        masscan_save_state(masscan);
    }



    /*
     * Now wait for all threads to exit
     */
    now = time(0);
    for (;;) {
        unsigned transmit_count = 0;
        unsigned receive_count = 0;
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* Find the minimum index of all the threads */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }


        status_print(&status, min_index, range, rate,
            total_tcbs, total_synacks, total_syns,
            masscan->wait - (time(0) - now));

        if (time(0) - now >= masscan->wait)
            control_c_pressed_again = 1;

        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            transmit_count += parms->done_transmitting;
            receive_count += parms->done_receiving;

        }

        pixie_mssleep(100);

        if (transmit_count < masscan->nic_count)
            continue;
        control_c_pressed = 1;
        control_c_pressed_again = 1;
        if (receive_count < masscan->nic_count)
            continue;
        break;
    }

    LOG(0, "EXITING main thread\n");

    /*
     * Now cleanup everything
     */
    status_finish(&status);
    rangelist_pick2_destroy(picker);

    return scope.Close(Undefined());
  }

  return scope.Close(Undefined());

}
