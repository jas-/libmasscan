{
	"targets":
	[{
		"target_name": "masscan",
		"type": "shared_library",
    "variables": {
      'cwd': '<!(pwd)',
      'path': 'src/masscan/src',
      'ldpath': 'build/Release',
#      'copy': '<!(cp <(path)/main.c <(path)/main.orig)',
#      'replace': "<!(sed '/^int main.*/,/^}/d' <(path)/main.orig > <(path)/main.c)",
    },
    "include_dirs": [
      "<(path)/src",
    ],
    "conditions": [
      ['OS=="linux"', {
#        "copies": {
#          'destination': '/lib64',
#          'files': [
#            '/lib64/masscan.so',
#          ]
#        },
        "cflags": [
          "-ggdb",
          "-O3",
          "-fPIC",
          "-std=gnu99",
          "-w",
          "-Wl,--whole-archive"
        ],
        "link_settings": {
          "libraries": [
            "-pthread",
            "-lpcap",
            "-lrt",
            "-ldl",
            "-lm"
          ]
        },
      }]
    ],
    "sources": [
      "<(path)/crypto-base64.c",
      "<(path)/crypto-blackrock2.c",
      "<(path)/event-timeout.c",
      "<(path)/in-binary.c",
      "<(path)/logger.c",
      "<(path)/main-conf.c",
      "<(path)/main-dedup.c",
      "<(path)/main-initadapter.c",
      "<(path)/main-listscan.c",
      "<(path)/main-ptrace.c",
      "<(path)/main-readrange.c",
      "<(path)/main.c",
      "<(path)/main-src.c",
      "<(path)/main-status.c",
      "<(path)/main-throttle.c",
      "<(path)/masscan-app.c",
      "<(path)/out-binary.c",
      "<(path)/out-certs.c",
      "<(path)/out-grepable.c",
      "<(path)/out-json.c",
      "<(path)/out-null.c",
      "<(path)/out-redis.c",
      "<(path)/out-text.c",
      "<(path)/out-unicornscan.c",
      "<(path)/out-xml.c",
      "<(path)/output.c",
      "<(path)/pixie-backtrace.c",
      "<(path)/pixie-file.c",
      "<(path)/pixie-threads.c",
      "<(path)/pixie-timer.c",
      "<(path)/proto-arp.c",
      "<(path)/proto-banner1.c",
      "<(path)/proto-dns.c",
      "<(path)/proto-ftp.c",
      "<(path)/proto-http.c",
      "<(path)/proto-icmp.c",
      "<(path)/proto-imap4.c",
      "<(path)/proto-interactive.c",
      "<(path)/proto-netbios.c",
      "<(path)/proto-ntp.c",
      "<(path)/proto-pop3.c",
      "<(path)/proto-preprocess.c",
      "<(path)/proto-sctp.c",
      "<(path)/proto-smtp.c",
      "<(path)/proto-snmp.c",
      "<(path)/proto-ssh.c",
      "<(path)/proto-ssl-test.c",
      "<(path)/proto-ssl.c",
      "<(path)/proto-tcp-telnet.c",
      "<(path)/proto-tcp.c",
      "<(path)/proto-udp.c",
      "<(path)/proto-vnc.c",
      "<(path)/proto-x509.c",
      "<(path)/proto-zeroaccess.c",
      "<(path)/rand-blackrock.c",
      "<(path)/rand-lcg.c",
      "<(path)/rand-primegen.c",
      "<(path)/ranges.c",
      "<(path)/rawsock.c",
      "<(path)/rawsock-arp.c",
      "<(path)/rawsock-getif.c",
      "<(path)/rawsock-getip.c",
      "<(path)/rawsock-getmac.c",
      "<(path)/rawsock-getroute.c",
      "<(path)/rawsock-pcapfile.c",
      "<(path)/rawsock-pfring.c",
      "<(path)/rawsock.c",
      "<(path)/rte-ring.c",
      "<(path)/script-ntp-monlist.c",
      "<(path)/script.c",
      "<(path)/siphash24.c",
      "<(path)/smack1.c",
      "<(path)/smackqueue.c",
      "<(path)/string_s.c",
      "<(path)/syn-cookie.c",
      "<(path)/templ-payloads.c",
      "<(path)/templ-pkt.c",
      "<(path)/xring.c",
      ]
  },
  {
		"target_name": "libmasscan",
		"type": "loadable_module",
    "variables": {
      'cwd': '<!(pwd)',
      'path': 'src/zmap-1.2.1',
      'ldpath': 'build/Release',
    },
		"include_dirs": [
			"<(path)/lib",
			"<(path)/src",
	  ],
		"dependencies": [
			"masscan",
		],
		"sources": [
			"src/output.cc",
			"src/config.cc",
			"src/scan.cc",
			"src/libmasscan.cc",
		],
		"conditions": [
      ['OS=="linux"', {
        "libraries":[
          "<(cwd)/<(ldpath)/masscan.so"
        ],
        "cflags": [
          "-O3",
				],
			}]
		],
	}]
}
