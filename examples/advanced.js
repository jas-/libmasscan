'use strict';

// Finds every network interface that has an IPv4 or IPv6 address, starts one scan for each,
// and prints one JSON object with the open ports grouped by address.
//
//   sudo node examples/advanced.js
//
// It works with no changes: when RANGES is empty, each interface scans its own IPv4 network.
// To run it as an ordinary user on Linux, see "Run without root" in the README.
//
//   sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v node)")"
//   node examples/advanced.js

const { execFileSync } = require('node:child_process');
const net = require('node:net');
const os = require('node:os');
const masscan = require('..'); // in your project: require('libmasscan')

// ---- Change these values ----

// Targets. A range goes to the interface that is on the same network. A range that is on
// no local network goes to the interface that has the default route.
const RANGES = [
  // '192.168.1.0/24',
  // '2001:db8::/120',
];

// Addresses that must not get packets.
const EXCLUDE = [
  // '192.168.1.1',
];

const PORTS = '22,80,443,8080';
const EXCLUDE_PORTS = '';
const RATE = 1000; // packets per second
const WAIT = 2; // seconds to wait for late replies after the last packet. masscan's default is 10.

// The MAC address that gets the packets of an interface. An entry here is necessary only when
// the lookup in routerMac() finds nothing and masscan stops with "ARP timed-out", for example
// on an interface that has no gateway.
const ROUTER_MAC = {
  // eth1: '66-55-44-33-22-11',
};

// ---- Interfaces ----

function isLinkLocal(address) {
  return /^fe[89ab]/i.test(address) || address.startsWith('169.254.');
}

// Returns [{ name, addresses: ['10.0.0.5/24', ...] }] for interfaces with a usable address.
function interfaces() {
  const found = [];
  for (const [name, entries] of Object.entries(os.networkInterfaces())) {
    const usable = entries.filter((e) => !e.internal && !isLinkLocal(e.address));
    if (usable.length > 0) found.push({ name, addresses: usable.map((e) => e.cidr) });
  }
  return found;
}

// The IPv4 network of an address. Networks larger than /24 are cut to /24 to keep the scan short.
function ownNetwork(cidr) {
  const [address, length] = cidr.split('/');
  if (!net.isIPv4(address)) return null;
  const prefix = Math.max(Number(length), 24);
  const size = 2 ** (32 - prefix);
  const value = address.split('.').reduce((sum, octet) => sum * 256 + Number(octet), 0);
  const base = Math.floor(value / size) * size;
  const octets = [24, 16, 8, 0].map((shift) => Math.floor(base / 2 ** shift) % 256);
  return `${octets.join('.')}/${prefix}`;
}

function isOnNetwork(iface, range) {
  const first = range.split(/[/-]/)[0];
  const family = net.isIPv6(first) ? 'ipv6' : 'ipv4';
  const list = new net.BlockList();
  for (const cidr of iface.addresses) {
    const [address, length] = cidr.split('/');
    list.addSubnet(address, Number(length), net.isIPv6(address) ? 'ipv6' : 'ipv4');
  }
  return list.check(first, family);
}

// Returns one job for each interface that has targets: [{ name, addresses, range }].
function plan() {
  const found = interfaces();
  if (RANGES.length === 0) {
    return found
      .map((iface) => ({ ...iface, range: iface.addresses.map(ownNetwork).filter(Boolean) }))
      .filter((job) => job.range.length > 0);
  }

  const jobs = found.map((iface) => ({ ...iface, range: RANGES.filter((r) => isOnNetwork(iface, r)) }));
  const remote = RANGES.filter((r) => !found.some((iface) => isOnNetwork(iface, r)));
  // No interface name: masscan uses the interface that has the default route.
  if (remote.length > 0) jobs.push({ name: null, addresses: [], range: remote });
  return jobs.filter((job) => job.range.length > 0);
}

// ---- Router MAC ----

function run(command, args) {
  try {
    return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 2000 });
  } catch {
    return '';
  }
}

// 'e0:db:d1:3:5e:cc' becomes 'e0-db-d1-03-5e-cc'. macOS prints octets without the leading zero.
function formatMac(text) {
  const octets = text.split(':');
  if (octets.length !== 6 || !octets.every((o) => /^[0-9a-f]{1,2}$/i.test(o))) return undefined;
  const mac = octets.map((o) => o.padStart(2, '0').toLowerCase()).join('-');
  return mac === '00-00-00-00-00-00' ? undefined : mac;
}

// The MAC address of the gateway of an interface, from the neighbor table of the system.
function gatewayMac(name) {
  let gateway;
  let entry;
  if (process.platform === 'linux') {
    gateway = /^default via (\S+)/m.exec(run('ip', ['-4', 'route', 'show', 'default', 'dev', name]))?.[1];
    if (!gateway) return undefined;
    entry = /lladdr (\S+)/.exec(run('ip', ['-4', 'neigh', 'show', gateway, 'dev', name]));
  } else if (process.platform === 'darwin') {
    gateway = /^\s*gateway: (\S+)/m.exec(run('route', ['-n', 'get', '-ifscope', name, 'default']))?.[1];
    if (!gateway) return undefined;
    entry = / at (\S+) on /.exec(run('arp', ['-n', '-i', name, gateway]));
  }
  return entry ? formatMac(entry[1]) : undefined;
}

// ROUTER_MAC has priority. Then the gateway of the interface. When the result is undefined,
// masscan finds the router with its own ARP request.
function routerMac(name) {
  if (name === null) return undefined;
  return ROUTER_MAC[name] ?? gatewayMac(name);
}

// ---- Scans ----

// masscan permits one scan at a time in a process. All jobs start together, and this queue
// gives each one its turn.
let queue = Promise.resolve();

// The line of the masscan log that names the failure.
function reason(err) {
  const line = err.message.split('\n').find((l) => l.includes('FAIL')) ?? err.message;
  const text = line.replace(/^\[-\] FAIL: /, '');
  return /ARP timed-out/.test(text) ? `${text}. Set ROUTER_MAC for this interface.` : text;
}

function scan(job) {
  const mac = routerMac(job.name);
  const opts = {
    iface: job.name ?? undefined,
    routerMac: mac,
    range: job.range,
    exclude: EXCLUDE,
    ports: PORTS,
    excludePorts: EXCLUDE_PORTS || undefined,
    rate: RATE,
    wait: WAIT,
  };
  const summary = { interface: job.name ?? 'default', addresses: job.addresses, routerMac: mac ?? null, range: job.range };

  const result = queue.then(() => masscan.scan(opts).done).then(
    (report) => ({ ...summary, durationMs: report.durationMs, hosts: report.hosts }),
    (err) => ({ ...summary, error: reason(err), hosts: [] }),
  );
  queue = result;
  return result;
}

async function main() {
  const startedAt = new Date();
  const scans = await Promise.all(plan().map(scan));

  // One entry for each address, also when two interfaces found the same address.
  const hosts = new Map();
  for (const { hosts: found } of scans) {
    for (const { ip, ports } of found) {
      const host = hosts.get(ip) ?? { ip, ports: [] };
      for (const p of ports) {
        if (!host.ports.some((q) => q.port === p.port && q.protocol === p.protocol)) host.ports.push(p);
      }
      host.ports.sort((a, b) => a.port - b.port);
      hosts.set(ip, host);
    }
  }

  console.log(JSON.stringify({
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    interfaces: scans.map(({ hosts: found, ...rest }) => ({ ...rest, hosts: found.length })),
    hosts: [...hosts.values()],
  }, null, 2));
}

main().catch((err) => {
  console.error(err.message);
  process.exitCode = 1;
});
