#include <string.h>
#include <node.h>
#include <v8.h>

#include "./libmasscan.h"

extern "C" {
#include "masscan/src/masscan.h"
#include "masscan/src/masscan-version.h"
#include "masscan/src/ranges.h"
#include "masscan/src/string_s.h"
#include "masscan/src/logger.h"
#include "masscan/src/proto-banner1.h"
#include "masscan/src/templ-payloads.h"
#include "masscan/src/templ-port.h"
#include "masscan/src/crypto-base64.h"
#include "masscan/src/script.h"
#include "masscan/src/masscan-app.h"

#include <ctype.h>
#include <limits.h>
}

using namespace node;
using namespace v8;

void libmasscan::Config(Handle<Object> obj) {
	HandleScope scope;
	libmasscan masscan;
  struct Masscan masscan[1];

	/* Disable all logging and verbosity */

	masscan.ConfigIface(obj);
	masscan.ConfigIpaddr(obj);
	masscan.ConfigHwaddr(obj);
	masscan.ConfigRange(obj);
	masscan.ConfigBandwidth(obj);
	masscan.ConfigBlacklist(obj);
	masscan.ConfigWhitelist(obj);

	masscan.ConfigWhiteBlackLists();
	masscan.ConfigTargets();
	masscan.ConfigCores();
	masscan.ConfigSeed();

	masscan.ConfigProbeModule(obj);
	masscan.ConfigOutputModule(obj);
	masscan.ConfigShards(obj);
	masscan.ConfigShardTotal(obj);
	masscan.ConfigThreads(obj);
}

void libmasscan::ConfigIface(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("iface"))) {
		Handle<v8::Value> value = obj->Get(String::New("iface"));

	} else {

	}
}

void libmasscan::ConfigIpaddr(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("ipaddr"))) {
		Handle<v8::Value> value = obj->Get(String::New("ipaddr"));
		//zconf.source_ip_first =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(zconf.source_ip_first, *v8::String::Utf8Value(value->ToString()));

		//char *dash = strchr(zconf.source_ip_first, '-');

		//if (dash) {
		//	*dash = '\0';
		//	zconf.source_ip_last = dash+1;
		//} else {
		//	zconf.source_ip_last = zconf.source_ip_first;
		//}

	} else {
		//struct in_addr default_ip;
		//zconf.source_ip_first = (char*) xmalloc(INET_ADDRSTRLEN);
		//if (get_iface_ip(zconf.iface, &default_ip) < 0) {
		//	ThrowException(Exception::TypeError(
		//		String::New("Could not detect IP, specify as ipaddr")));
		//}
		//zconf.source_ip_last = zconf.source_ip_first;
		//inet_ntop(AF_INET, &default_ip, zconf.source_ip_first, INET_ADDRSTRLEN);
	}
}

/*
#define MAC_LEN ETHER_ADDR_LEN
int libmasscan::parse_mac(macaddr_t *out, char *in)
{
	if (strlen(in) < MAC_LEN*3-1)
		return 0;

	char octet[4];
	octet[2] = '\0';
	for (int i=0; i < MAC_LEN; i++) {
		if (i < MAC_LEN-1 && in[i*3+2] != ':') {
			return 0;
		}
		strncpy(octet, &in[i*3], 2);
		char *err = NULL;
		long b = strtol(octet, &err, 16);
		if (err && *err != '\0') {
			return 0;
		}
		out[i] = b & 0xFF;
	}
	return 1;
}
*/
void libmasscan::ConfigHwaddr(Handle<Object> obj) {
	HandleScope scope;
	libmasscan masscan;
	//struct gengetopt_args_info args;

	if (obj->Has(v8::String::NewSymbol("mac"))) {
		Handle<v8::Value> value = obj->Get(String::New("mac"));
		//args.gateway_mac_arg =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(args.gateway_mac_arg, *v8::String::Utf8Value(value->ToString()));
		//if (!masscan.parse_mac(zconf.gw_mac, args.gateway_mac_arg)) {
		//	ThrowException(Exception::TypeError(
		//		String::New("Invalid gateway MAC address")));
		//}
		//zconf.gw_mac_set = 1;
	} else {
		//struct in_addr gw_ip;
		//if (get_default_gw(&gw_ip, zconf.iface) < 0) {
		//	ThrowException(Exception::TypeError(
		//		String::New("Could not detect gateway MAC address")));
		//}
		//zconf.gw_ip = gw_ip.s_addr;

		//if (get_hw_addr(&gw_ip, zconf.iface, zconf.gw_mac)) {
		//	ThrowException(Exception::TypeError(
		//		String::New("Could not detect gateway MAC address")));
		//}
		//zconf.gw_mac_set = 1;
	}
}

void libmasscan::ConfigRange(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("range"))) {
		Handle<v8::Value> value = obj->Get(String::New("range"));
		//zconf.destination_cidrs =
		//	(char**) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy((char*) zconf.destination_cidrs,
		//				*v8::String::Utf8Value(value->ToString()));
		//zconf.destination_cidrs_len =
		//	strlen(*v8::String::Utf8Value(value->ToString()));
	}
}

void libmasscan::ConfigBlacklist(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("blacklist"))) {
		Handle<v8::Value> value = obj->Get(String::New("blacklist"));
		//zconf.blacklist_filename =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(zconf.blacklist_filename, *v8::String::Utf8Value(value->ToString()));
	}
}

void libmasscan::ConfigWhitelist(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("whitelist"))) {
		Handle<v8::Value> value = obj->Get(String::New("whitelist"));
		//zconf.whitelist_filename =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(zconf.whitelist_filename, *v8::String::Utf8Value(value->ToString()));
	}
}

void libmasscan::ConfigWhiteBlackLists(void) {
	HandleScope scope;

	//if (blacklist_init(zconf.whitelist_filename, zconf.blacklist_filename,
	//			zconf.destination_cidrs, zconf.destination_cidrs_len,
	//			NULL, 0)) {
	//	ThrowException(Exception::TypeError(
	//		String::New("Could not initialize whitelist/blacklists specified")));
	//}
}

void libmasscan::ConfigTargets(void) {
	HandleScope scope;

/*
	uint64_t allowed = blacklist_count_allowed();
	assert(allowed <= (1LL << 32));
	if (allowed == (1LL << 32)) {
		zsend.targets = 0xFFFFFFFF;
	} else {
		zsend.targets = allowed;
	}
	if (zsend.targets > zconf.max_targets) {
		zsend.targets = zconf.max_targets;
	}
*/
}

void libmasscan::ConfigShards(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("shards"))) {
		Handle<v8::Value> value = obj->Get(String::New("shards"));
		//zconf.shard_num = value->NumberValue();
	} else {
		//zconf.shard_num = 0;
	}
}

void libmasscan::ConfigShardTotal(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("shardtotal"))) {
		Handle<v8::Value> value = obj->Get(String::New("shartotal"));
		//zconf.total_shards = value->NumberValue();
	} else {
		//zconf.total_shards = 1;
	}
}

void libmasscan::ConfigCores(void) {
	HandleScope scope;
	libmasscan masscan;

	//int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	//zconf.senders = masscan.max(num_cores - 1, 1);
	//if (!zconf.quiet) {
	//	zconf.senders = masscan.max(zconf.senders - 1, 1);
	//}

	//if (zconf.senders > zsend.targets) {
	//	zconf.senders = max(zsend.targets, 1);
	//}
}

void libmasscan::ConfigSeed(void) {
	HandleScope scope;

	//if (zconf.use_seed) {
	//	aesrand_init(zconf.seed + 1);
	//} else {
	//	aesrand_init(0);
	//}
}

void libmasscan::ConfigProbeModule(Handle<Object> obj) {
	HandleScope scope;
	libmasscan masscan;
	//struct gengetopt_args_info args;

	if (obj->Has(v8::String::NewSymbol("probemodule"))) {
		Handle<v8::Value> value = obj->Get(String::New("probemodule"));
		//args.probe_module_arg =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(args.probe_module_arg, *v8::String::Utf8Value(value->ToString()));
	} else {
		//args.probe_module_arg = (char*) xmalloc(strlen("icmp_echoscan") + 1);
		//strcpy(args.probe_module_arg, "icmp_echoscan");
	}

	//zconf.probe_module = get_probe_module_by_name(args.probe_module_arg);
	//if (!zconf.probe_module) {
	//	ThrowException(Exception::TypeError(
	//		String::New("probe module does not exist")));
	//}

	//memset(&zconf.fsconf, 0, sizeof(struct fieldset_conf));

	//fielddefset_t *fds = &(zconf.fsconf.defs);
	//gen_fielddef_set(fds, (fielddef_t*) &(ip_fields), ip_fields_len);
	//gen_fielddef_set(fds, zconf.probe_module->fields,
	//								 zconf.probe_module->numfields);
	//gen_fielddef_set(fds, (fielddef_t*) &(sys_fields), sys_fields_len);

	//args.output_module_arg = (char*) xmalloc(sizeof(struct fieldset_conf));

	//for (int i = 0; i < fds->len; i++) {
	//	masscan.strncat(args.output_module_arg, fds->fielddefs[i].name,
	//						 strlen(fds->fielddefs[i].name));
	//	masscan.strncat(args.output_module_arg, ",", strlen(","));
	//}
	//args.output_module_arg[strlen(args.output_module_arg) - 1] = '\0';
	//zconf.raw_output_fields = args.output_module_arg;
}

char* libmasscan::strncat(char *dest, const char *src, size_t n) {
  size_t dest_len = strlen(dest);
  size_t i;

	for (i = 0 ; i < n && src[i] != '\0' ; i++)
		dest[dest_len + i] = src[i];

	dest[dest_len + i] = '\0';

	return dest;
}

void libmasscan::ConfigOutputModule(Handle<Object> obj) {
	HandleScope scope;
	libmasscan masscan;
	//struct gengetopt_args_info args;

	//args.probe_module_arg = (char*) xmalloc(strlen("node-json") + 1);
	//strcpy(args.probe_module_arg, "node-json");

	//zconf.output_module = get_output_module_by_name(args.probe_module_arg);

	//zconf.filter_duplicates = 1;
	//zconf.filter_unsuccessful = 1;

	//masscan.split_string(zconf.raw_output_fields, &(zconf.output_fields_len),
	//								&(zconf.output_fields));

	//fs_generate_fieldset_translation(&zconf.fsconf.translation,
	//																 &zconf.fsconf.defs, zconf.output_fields,
	//																 zconf.output_fields_len);

	//if (!zconf.probe_module) {
	//	ThrowException(Exception::TypeError(
	//		String::New("output module does not exist")));
	//}
}

void libmasscan::split_string(char* in, int *len, char***results)
{
/*
	char** fields = (char**) xcalloc(MAX_FIELDS, sizeof(char*));
	int retvlen = 0;
	char *currloc = in;

	while (1) {
		size_t len = strcspn(currloc, ", ");
		if (len == 0) {
			currloc++;
		} else {
			char *newstr = (char*) xmalloc(len+1);
			strncpy(newstr, currloc, len);
			newstr[len] = '\0';
			fields[retvlen++] = newstr;
			assert(fields[retvlen-1]);
		}
		if (len == strlen(currloc)) {
			break;
		}
		currloc += len;
	}
	*results = fields;
	*len = retvlen;
*/
}

void libmasscan::ConfigBandwidth(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("bandwidth"))) {
		Handle<v8::Value> value = obj->Get(String::New("bandwidth"));
		//zconf.bandwidth = atoi(*v8::String::Utf8Value(value->ToString()));
		//char *suffix =
		//	(char*) xmalloc(strlen(*v8::String::Utf8Value(value->ToString())) + 1);
		//strcpy(suffix, *v8::String::Utf8Value(value->ToString()));

/*
		while (*suffix >= '0' && *suffix <= '9') {
			suffix++;
		}

		if (*suffix) {
			switch (*suffix) {
			case 'G': case 'g':
				zconf.bandwidth *= 1000000000;
				break;
			case 'M': case 'm':
				zconf.bandwidth *= 1000000;
				break;
			case 'K': case 'k':
				zconf.bandwidth *= 1000;
				break;
			default:
				ThrowException(Exception::TypeError(
					String::New("Bandwidth suffix is invalid")));
			}
		}
*/
	}
}

void libmasscan::ConfigThreads(Handle<Object> obj) {
	HandleScope scope;

	if (obj->Has(v8::String::NewSymbol("threads"))) {
		Handle<v8::Value> value = obj->Get(String::New("threads"));
		//zconf.senders = value->NumberValue();
	} else {
		//int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
		//zconf.senders = max(num_cores - 1, 1);
		//if (!zconf.quiet) {
		//	zconf.senders = max(zconf.senders - 1, 1);
		//}
	}

	//if (zconf.senders > zsend.targets) {
	//	zconf.senders = max(zsend.targets, 1);
	//}
}

#if defined(__APPLE__)
void libmasscan::set_cpu(void) {
	//pthread_mutex_lock(&cpu_affinity_mutex);
	//static int core=0;
	//int num_cores = sysconf(_SC_NPROCESSORS_ONLN);

	//mach_port_t tid = pthread_mach_thread_np(pthread_self());
	//struct thread_affinity_policy policy;
	//policy.affinity_tag = core;
	//kern_return_t ret = thread_policy_set(tid,THREAD_AFFINITY_POLICY,
	//				(thread_policy_t) &policy,THREAD_AFFINITY_POLICY_COUNT);
	//if (ret != KERN_SUCCESS) {
	//	ThrowException(Exception::TypeError(
	//		String::New("Cannot set CPU affinity")));
	//}
	//core = (core + 1) % num_cores;

	//pthread_mutex_unlock(&cpu_affinity_mutex);
}

#else

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/param.h>
#include <sys/cpuset.h>
#define cpu_set_t cpuset_t
#endif

void libmasscan::set_cpu(void) {
	pthread_mutex_lock(&cpu_affinity_mutex);
	static int core=0;
	int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
	cpu_set_t cpuset;
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
		ThrowException(Exception::TypeError(
			String::New("Can't set thread CPU affinity")));
	}
	core = (core + 1) % num_cores;
	pthread_mutex_unlock(&cpu_affinity_mutex);
}
#endif

void libmasscan::drop_privs() {
	HandleScope scope;
	struct passwd *pw;

	if (geteuid() != 0) {
		ThrowException(Exception::TypeError(
			String::New("Unable to drop privileges")));
	}

	if ((pw = getpwnam("nobody")) != NULL) {
		if (setuid(pw->pw_uid) == 0) {
			return;
		}
	}

	ThrowException(Exception::TypeError(
		String::New("Unable to drop privileges")));
}
