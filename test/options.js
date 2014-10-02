var lib = require('../build/Release/masscan.node')
  , opts = {
//      iface: 'eth0',
//      ports: '22,80,443,3306-10000',
      ports: '22',
//      excludeports: '9000',
      range: [
        '10.0.2.0/24',
        '192.168.2.0/25',
        '190.8.32.0/20',
      ],
      exclude: [
        '0.0.0.0/8', // RFC1122: "This host on this network"
        '10.0.0.0/8', // RFC1918: Private-Use
        '100.64.0.0/10', // RFC6598: Shared Address Space
        '127.0.0.0/8', // RFC1122: Loopback
        '169.254.0.0/16', // RFC3927: Link Local
        '172.16.0.0/12', // RFC1918: Private-Use
        '192.0.0.0/24', // RFC6890: IETF Protocol Assignments
        '192.0.2.0/24', // RFC5737: Documentation (TEST-NET-1)
        '192.88.99.0/24', // RFC3068: 6to4 Relay Anycast
        '192.168.0.0/16', // RFC1918: Private-Use
        '198.18.0.0/15', // RFC2544: Benchmarking
        '198.51.100.0/24', // RFC5737: Documentation (TEST-NET-2)
        '203.0.113.0/24', // RFC5737: Documentation (TEST-NET-3)
        '240.0.0.0/4', // RFC1112: Reserved
        '255.255.255.255/32', // RFC0919: Limited Broadcast
        '224.0.0.0/4', // RFC5771: Multicast/Reserved
      ]
    };

lib.masscan(opts, function(err, report) {
  if (err) throw new Error(err);
  console.log(report);
});
