# libmasscan

Node.js bindings for the [masscan](https://github.com/robertdavidgraham/masscan) port scanner. Masscan runs inside the Node.js process as native code. It does not run as a child process. Results go to JavaScript as events, and the event loop never blocks.

libmasscan is a module only. It has no command-line tool. To run a scan, call `scan()` from your own code.

## Requirements

- Linux or macOS.
- Node.js 18 or later, and a C compiler for `node-gyp`.
- libpcap at run time. Masscan loads it dynamically.
- Root, or `CAP_NET_RAW` on Linux, for live scans.

## Install

The package is not on the npm registry yet. Install it with npm from the GitHub repository, or clone it with git.

Both methods compile masscan with `node-gyp`. Before the build, the install script gets the masscan sources:

1. If `src/masscan` already has the sources, the install uses them.
2. In a git clone, the install runs `git submodule update --init --recursive`.
3. In other cases, the install downloads the masscan commit that `masscan.commit` in `package.json` pins.

You do not need to fetch the submodule yourself.

### With npm

Add libmasscan as a dependency of your project:

```sh
cd my-project
npm install github:jas-/libmasscan
```

To install a specific commit or tag, add it after `#`:

```sh
npm install github:jas-/libmasscan#<commit-or-tag>
```

### With git

Clone the repository and build it:

```sh
git clone https://github.com/jas-/libmasscan.git
cd libmasscan
npm install
npm test
```

Then add the clone as a dependency of your project:

```sh
cd my-project
npm install /path/to/libmasscan
```

### After the install

`require('libmasscan')` or `import masscan, { scan } from 'libmasscan'` gives you the API.

Newer npm versions warn about install scripts that you have not approved. If npm skips the build, run `npm install-scripts approve libmasscan`, then `npm rebuild libmasscan`.

On Linux, you can give the Node.js binary raw-socket access so that it does not need root:

```sh
sudo setcap cap_net_raw+ep "$(command -v node)"
```

`examples/consumer/` is a separate project that installs libmasscan from a local path and checks that the import works. It takes no command-line arguments. It reads `config.json`, and passes its `options` object to `scan()` unchanged:

```json
{
  "options": {
    "range": ["10.0.0.0/29", "10.0.1.0/30"],
    "exclude": ["10.0.0.7"],
    "ports": "22,80,443,8000-8010",
    "excludePorts": "8005",
    "rate": 10000,
    "wait": 0,
    "offline": true,
    "adapter": "lo",
    "adapterIp": "10.9.9.9",
    "adapterMac": "00-11-22-33-44-55",
    "routerMac": "66-55-44-33-22-11"
  },
  "timeoutMs": 30000
}
```

- `options` holds libmasscan options, with the names and values in [Options](#options). Any masscan option works, for example `includeFile`, `excludeFile`, `seed`, `banners` or `resumeIndex`.
- `timeoutMs` (optional) stops the scan after that time. The report then has `timedOut: true` and a `resumeIndex`.
- `$comment` is ignored. Any other top-level key is an error.

The shipped `config.json` runs in offline mode, so it needs no root and sends no packets. For a live scan, copy `config.live.example.json` to `config.json` and edit the targets.

```sh
cd examples/consumer
npm install
npm start         # check lines on stderr, the JSON report on stdout; exit 0 if all pass
sudo npm start    # after you put a live configuration in config.json
npm start --silent > report.json   # --silent keeps npm's "> start" lines out of the file
```

Make `timeoutMs` long enough for the scan: the number of probes (addresses × ports) divided by `rate`, plus `wait`. Your application must run as root, or with `CAP_NET_RAW` on Linux, to send packets.

Scan only networks that you own or have permission to scan.

## Examples

Examples 2 to 5 use `await` at the top level. Run them in an ES module (an `.mjs` file, with `import masscan from 'libmasscan'`) or put them inside an `async` function. In CommonJS, top-level `await` is a syntax error.

### 1. Events

`scan()` starts a scan at once and returns an EventEmitter. Results arrive while the scan runs.

```js
const masscan = require('libmasscan');

const scan = masscan.scan({
  range: ['10.0.2.0/24', '192.168.2.0/25'],
  ports: '22,80,443,3306-10000',
  excludePorts: '9000-9999',
  rate: 10000,
});

scan.on('result', (r) => console.log(r));
// { ip: '10.0.2.15', port: 22, protocol: 'tcp', status: 'open',
//   ttl: 64, reason: 'syn-ack', timestamp: 1763436000000 }

scan.on('progress', (p) => console.log(`${p.percent?.toFixed(1)}% at ${Math.round(p.rate)} pps`));
scan.on('error', (err) => console.error(err.message));
scan.on('done', (report) => console.log('done', report.counts));
```

### 2. JSON results

`scan.done` is a promise. It resolves when the scan ends, with a report of the whole scan. The report is plain data, so `JSON.stringify()` gives the scan results as JSON:

```js
const masscan = require('libmasscan');

const report = await masscan.scan({ range: '192.168.1.0/24', ports: '22,80,443', rate: 5000, wait: 5 }).done;
console.log(JSON.stringify(report, null, 2));
```

```json
{
  "startedAt": "2026-11-18T12:00:00.000Z",
  "finishedAt": "2026-11-18T12:00:09.000Z",
  "durationMs": 9012,
  "resumeIndex": null,
  "counts": { "results": 3, "open": 3, "closed": 0, "banners": 0 },
  "results": [
    { "ip": "192.168.1.20", "port": 22, "protocol": "tcp", "status": "open",
      "ttl": 64, "reason": "syn-ack", "timestamp": 1795003201000 },
    { "ip": "192.168.1.31", "port": 80, "protocol": "tcp", "status": "open",
      "ttl": 64, "reason": "syn-ack", "timestamp": 1795003202000 },
    { "ip": "192.168.1.31", "port": 443, "protocol": "tcp", "status": "open",
      "ttl": 64, "reason": "syn-ack", "timestamp": 1795003202000 }
  ],
  "banners": []
}
```

The same report is the payload of the `done` event. If masscan refuses the options, `scan.done` rejects with an `Error`, and `err.report` holds what the scan found before it failed.

`results` and `banners` keep every event in memory. For a scan with millions of results, set `collect: false`: the arrays stay empty, `counts` still grows, and you read each result from the `result` event as it arrives.

### 3. A reusable scanner module for applications

A process runs one scan at a time (see [Limits](#limits)). An application that gets scan requests from many places needs a queue. `examples/scanner.js` is a small module for this. Copy it into your project, or require it. It adds:

- **A queue.** Calls to `scan()` wait for their turn and never throw `ERR_MASSCAN_BUSY`. A scan that fails does not block the scans after it.
- **Defaults** that apply to every scan, for example the rate and an exclude list.
- **A time limit.** A scan that runs too long stops, and the report holds the resume index.
- **The open ports grouped by host.** The report is the JSON report of example 2, plus `hosts` and `timedOut`.

```js
const { Scanner } = require('libmasscan/examples/scanner');

const scanner = new Scanner({
  rate: 5000,
  wait: 5,
  exclude: ['192.168.1.1'], // never scan the router
});

const report = await scanner.scan(
  { range: '192.168.1.0/24', ports: '22,80,443,8000-8100' },
  { timeoutMs: 60_000, onProgress: (p) => console.log(`${p.percent?.toFixed(0)}%`) },
);

console.log(JSON.stringify(report.hosts, null, 2));
// {
//   "192.168.1.20": { "ip": "192.168.1.20", "ports": [ { "port": 22, "protocol": "tcp", "ttl": 64 } ] },
//   "192.168.1.31": { "ip": "192.168.1.31", "ports": [ { "port": 80, "protocol": "tcp", "ttl": 64 },
//                                                      { "port": 443, "protocol": "tcp", "ttl": 64 } ] }
// }
console.log(report.timedOut, report.resumeIndex); // true and a number if the time limit stopped the scan
```

The same module behind an HTTP endpoint, with only Node.js built-ins:

```js
const http = require('node:http');
const { Scanner } = require('libmasscan/examples/scanner');

const scanner = new Scanner({ rate: 5000, wait: 5 });

// POST /scan  {"range": "192.168.1.0/24", "ports": "22,80,443"}
http.createServer(async (req, res) => {
  if (req.method !== 'POST' || req.url !== '/scan') {
    res.writeHead(404).end();
    return;
  }
  let body = '';
  for await (const chunk of req) body += chunk;
  try {
    const { range, ports } = JSON.parse(body);
    // Accept only the fields you expect. Do not pass a request body to
    // masscan as it is: masscan options include file paths.
    const report = await scanner.scan({ range, ports }, { timeoutMs: 120_000 });
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(report));
  } catch (err) {
    res.writeHead(400, { 'content-type': 'application/json' })
      .end(JSON.stringify({ error: err.message }));
  }
}).listen(8080, '127.0.0.1');
```

Two requests that arrive at the same time both succeed. The second waits in the queue until the first scan ends.

### 4. Banners

With `banners: true`, masscan completes the TCP connection and reads what the service sends. Give masscan a source IP that the operating system does not use. Otherwise the kernel resets each connection, because it does not know about the connection that masscan opened.

```js
const scan = masscan.scan({
  range: '192.168.1.0/24',
  ports: '21,22,25,80,443',
  banners: true,
  adapterIp: '192.168.1.250', // a free address on the local network
  wait: 5,
});

scan.on('banner', (b) => console.log(b.ip, b.port, b.service, JSON.stringify(b.banner)));
// 192.168.1.20 22 ssh "SSH-2.0-OpenSSH_9.6\r\n"
// 192.168.1.31 80 http.server "nginx/1.26.0"
await scan.done;
```

### 5. Stop and resume

`stop()` ends a scan early. The `done` payload then has a `resumeIndex`. To continue later, pass the index and the same `seed`, so that masscan visits the targets in the same random order:

```js
const options = { range: '10.0.0.0/16', ports: '80,443', rate: 1000, seed: 12345 };

const first = masscan.scan(options);
setTimeout(() => first.stop({ force: true }), 30_000);
const { resumeIndex } = await first.done;

if (resumeIndex !== null) {
  await masscan.scan({ ...options, resumeIndex }).done;
}
```

### The adapter and the router MAC

Masscan does not look up a route for each target. It sends every packet through one adapter, to one router MAC address. By default it takes both from the default route. A target that is not reachable through the default gateway gets no packets, so the scan ends with no results and no error.

This happens, for example, with a target on a second interface, in a container network, or behind a VPN that is not the default route. Set both values:

```js
masscan.scan({
  range: '10.77.0.0/24',
  ports: '1-1024',
  adapter: 'ms0',                 // the interface that reaches the targets
  routerMac: '46:4a:3c:99:c0:e7', // the gateway on that interface; for a target
                                  // on the same link, the target's own MAC
});
```

To see what masscan chose, set `verbose: 1` and read the `log` events that start with `[+] interface`, `[+] source-ip` and `[+] router-mac-ipv4`.

## Options

Any masscan option works. The rules for option names and values are:

- A camelCase key becomes a masscan option: `excludePorts` becomes `--exclude-ports`, and `adapterIp` becomes `--adapter-ip`.
- An array gives the option one time for each item.
- `true` turns on a flag. `false`, `null` and `undefined` are left out.
- `verbose: n` sets the log level. Higher levels send more `log` events.
- `args` is a list of raw masscan arguments, added at the end.

Common options:

| Option | Masscan option | Purpose |
|---|---|---|
| `range` | `--range` | Target addresses or CIDR ranges |
| `ports` | `--ports` | Ports, for example `'80,443,8000-8100'`. Use `U:53` for UDP. |
| `exclude` | `--exclude` | Addresses that the scan must not touch |
| `excludePorts` | `--exclude-ports` | Ports that the scan must not touch |
| `rate` | `--rate` | Packets per second (default 100) |
| `wait` | `--wait` | Seconds to wait for late responses after the last packet (default 10) |
| `banners` | `--banners` | Connect to open TCP ports and get banners |
| `adapter` | `--adapter` | Network interface. The default is the default route's interface. |
| `routerMac` | `--router-mac` | The MAC address that receives every packet. The default is the default gateway's. See [The adapter and the router MAC](#the-adapter-and-the-router-mac). |
| `adapterIp`, `adapterMac` | | Set these when masscan cannot find them, or for banners |
| `shard` | `--shard` | Divide the scan between machines, for example `'1/4'` |
| `resumeIndex` | `--resume-index` | Continue from a `resumeIndex`. Use the same `seed` as the first scan. |
| `collect` | (none) | `false` keeps `results` and `banners` out of the report. Not passed to masscan. |

The old option names `iface`, `excludeports` and `gateway` still work.

Masscan also reads `/etc/masscan/masscan.conf`, as the CLI does, so a system-wide exclude list applies to library scans too.

## Events

| Event | Data |
|---|---|
| `result` | `ip`, `port`, `protocol` (`tcp`, `udp`, `icmp`, `sctp`, `arp`), `status` (`open`, `closed`, `arp`), `ttl`, `reason` (TCP flags), `mac` (ARP), `timestamp` (ms) |
| `banner` | `ip`, `port`, `protocol`, `service`, `banner` (latin1 string of the raw bytes), `ttl`, `timestamp` |
| `progress` | `percent` (`null` for `infinite` scans), `rate`, `sent`, `synacks`, `tcbs`, `index`, `total`, `waitRemaining` (`null` while packets are sent) |
| `log` | `level`, `message`. These are masscan's messages. The module never writes to stdout or stderr. |
| `done` | The JSON report: `startedAt`, `finishedAt`, `durationMs`, `resumeIndex` (a number if the scan stopped early, or `null`), `counts`, `results`, `banners`. See [JSON results](#2-json-results). |
| `error` | An `Error` that has `exitCode`, `log` (masscan's last messages) and `report` |

The JavaScript thread gets events in batches, so a fast scan does not make one call for each result.

## Stop a scan

```js
scan.stop();                // stop sending, then wait `wait` seconds for responses
scan.stop({ force: true }); // stop at once
```

A second `stop()` has the same effect as `force: true`. These match the first and second Ctrl-C in the masscan CLI.

## Limits

- **One scan at a time in each process.** Masscan keeps global state. If you call `scan()` while a scan runs, it throws an error with the code `ERR_MASSCAN_BUSY`. You can start the next scan from a `done` or `error` handler. To run scans in parallel, use one worker process for each scan. In one process, use `rate` and `shard`.
- **Each scan takes at least about 3 seconds.** Upstream masscan waits 1 second before it sends, so that the receive thread is ready. It also waits `wait` seconds after the last packet. For large scans this cost is small.
- **Some failures are fatal.** Masscan calls `exit()` when it finds an error. Before the scan threads start, the module turns that call into an `error` event. If masscan calls `exit()` after the scan threads started, the module stops the scan, reports an error, and refuses all later scans. Restart the process in that case. Upstream does this only for internal failures, for example when the threads do not stop.
- **No Windows support.**

## How it works

`src/masscan` is the unmodified upstream masscan, included as a git submodule. `binding.gyp` compiles all upstream sources except four:

| Upstream file | Replacement |
|---|---|
| `main.c` | `src/runner.c` includes it, so that it can call the static `main_scan()` |
| `output.c` | `src/masscan-output.c` compiles it with renamed report functions. `src/hooks.c` sends each result to JavaScript and then calls the original, so file output such as `-oJ` still works. |
| `util-logger.c` | `src/hooks.c` sends log lines as events |
| `main-status.c` | `src/hooks.c` sends status lines as `progress` events |

`src/shim/libmasscan-shim.h` is force-included into every upstream file. It turns `exit()` into an error that the module can recover from. It also sends `fprintf(stderr, ...)` and `printf()` to the `log` event.

To update masscan, move the submodule to a new commit, set `masscan.commit` in `package.json` to that commit, and run `npm run build && npm test`. `npm pack` fails if the two commits are different. In most cases the build needs no other change. A change is necessary only when upstream changes `main()`, the logger, the status printer, or the output report functions.

## Tests

```sh
npm test
```

The tests do not need root. They use masscan's `--offline` mode, which runs all of the scan except the packet I/O.

## Credits

[masscan](https://github.com/robertdavidgraham/masscan) is the work of Robert David Graham and its contributors. libmasscan compiles the upstream source without changes, and does all scan work through it. The packet engine, protocol decoders, banner grabbers and output formats all come from masscan.

## License

AGPL-3.0, the same license as masscan.
