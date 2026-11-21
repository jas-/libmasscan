'use strict';

// Runs one scan and prints the report as JSON. This is the example from the README.
// Change `iface` and `range` to a network that you may scan, then run it as root:
//
//   sudo node examples/basic.js
//
// To run it as an ordinary user on Linux, give node the raw-socket capability one time:
//
//   sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v node)")"
//   node examples/basic.js

const masscan = require('..'); // in your project: require('libmasscan')

const opts = {
  ports: '22,80,443,3306-10000',
  excludeports: '9000-9999',
  range: [
    '10.0.2.0/24',
    '192.168.2.0/25',
  ],
  exclude: [
    '0.0.0.0/8', // RFC1122: "This host on this network"
    '100.64.0.0/10', // RFC6598: Shared Address Space
    '127.0.0.0/8', // RFC1122: Loopback
    '169.254.0.0/16', // RFC3927: Link Local
    '172.16.0.0/12', // RFC1918: Private-Use
    '192.0.0.0/24', // RFC6890: IETF Protocol Assignments
    '192.0.2.0/24', // RFC5737: Documentation (TEST-NET-1)
    '192.88.99.0/24', // RFC3068: 6to4 Relay Anycast
    '198.18.0.0/15', // RFC2544: Benchmarking
    '198.51.100.0/24', // RFC5737: Documentation (TEST-NET-2)
    '203.0.113.0/24', // RFC5737: Documentation (TEST-NET-3)
    '240.0.0.0/4', // RFC1112: Reserved
    '255.255.255.255/32', // RFC0919: Limited Broadcast
    '224.0.0.0/4', // RFC5771: Multicast/Reserved
  ],
};

masscan.scan(opts).done
  .then((report) => console.log(JSON.stringify(report, null, 2)))
  .catch((err) => console.error(err.message));
