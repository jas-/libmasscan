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
}

using namespace node;
using namespace v8;

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
    /* return error of missing targets to callback */
  }
  count_ports = rangelist_count(&masscan->ports);
  if (count_ports == 0) {
    /* return error of missing ports to callback */
  }
  range = count_ips * count_ports + (uint64_t)(masscan->retries * masscan->max_rate);


  if (rangelist_is_contains(&masscan->ports, Templ_ARP)) {
    if (masscan->ports.count != 1) {
      /* return error or ARP scan when using ports */
    }
  }

  if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude_ip) == 0) {
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
    if (err != 0)
      /* return error of network adapter init to callback */

    parms->adapter = masscan->nic[index].adapter;
    if (masscan->nic[index].src.ip.range == 0) {
      /* return error or IP address per adapter to callback */
    }


  }

  return scope.Close(Undefined());
}
