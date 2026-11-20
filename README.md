# libmasscan

Node.js bindings for the [masscan](https://github.com/robertdavidgraham/masscan) port scanner. Masscan runs inside the Node.js process, and results arrive as events.

## Requirements

- Linux or macOS, with Node.js 18 or later.
- `make`, `python3`, `gcc` and `g++` for `node-gyp`.
  - Debian/Ubuntu: `apt install build-essential python3 libpcap-dev`
  - Fedora/RHEL: `dnf install gcc gcc-c++ make python3 libpcap`
  - Alpine: `apk add build-base linux-headers python3 libpcap`
- Root, or `CAP_NET_RAW` on Linux, to send packets.

## Install

From npm:

```sh
npm install libmasscan
```

From git:

```sh
git clone https://github.com/jas-/libmasscan.git
cd libmasscan
npm install
```

The install gets the masscan sources and compiles them. You do not need to fetch the submodule yourself.

## Example use

```javascript
const masscan = require('libmasscan');

const opts = {
  iface: 'eth0',
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

const scan = masscan.scan(opts);

scan.on('result', (r) => console.log(r.ip, r.port, r.status));

scan.done
  .then((report) => console.log(report.counts))
  .catch((err) => console.error(err.message));
```

Any masscan option works. Write it in camelCase: `excludePorts` becomes `--exclude-ports`. The events are `result`, `banner`, `progress`, `log`, `done` and `error`. A process runs one scan at a time. For a queue around `scan()`, see `examples/scanner.js`.

Scan only networks that you own or have permission to scan.

## Credits

[masscan](https://github.com/robertdavidgraham/masscan) is the work of Robert David Graham and its contributors. libmasscan compiles it without changes.

## License

AGPL-3.0, the same license as masscan.
