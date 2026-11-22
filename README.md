# libmasscan

Node.js bindings for the [masscan](https://github.com/robertdavidgraham/masscan) port scanner. Masscan runs inside the Node.js process, and the scan results come back as one JSON report.

[![npm](https://img.shields.io/npm/v/libmasscan.svg)](https://npmjs.com/package/libmasscan) [![CI](https://github.com/jas-/libmasscan/actions/workflows/ci.yml/badge.svg)](https://github.com/jas-/libmasscan/actions/workflows/ci.yml) ![Downloads](https://img.shields.io/npm/dm/libmasscan.svg) [![Known Vulnerabilities](https://snyk.io/test/github/jas-/libmasscan/badge.svg?targetFile=package.json)](https://snyk.io/test/github/jas-/libmasscan?targetFile=package.json)

## Requirements

- Linux or macOS, with Node.js 18 or later.
- `make`, `gcc`, `g++` and `python3`. The install compiles masscan with `node-gyp`, which needs Python to make the build files.
- `libpcap`. Masscan loads it when a scan starts.
- Root, or `CAP_NET_RAW` on Linux, to send packets. See [Run without root](#run-without-root).

Example package requirements.

<details>
<summary>Debian, Ubuntu (apt)</summary>

```sh
sudo apt-get install build-essential python3 libpcap-dev nodejs npm
```
</details>

<details>
<summary>Fedora, RHEL, CentOS, Rocky, AlmaLinux (dnf)</summary>

```sh
sudo dnf install gcc gcc-c++ make python3 tar libpcap nodejs npm
```
</details>

<details>
<summary>openSUSE (zypper)</summary>

```sh
sudo zypper install gcc gcc-c++ make python3 libpcap1 nodejs npm
```
</details>

<details>
<summary>Arch Linux, Manjaro (pacman)</summary>

```sh
sudo pacman -S --needed base-devel python libpcap nodejs npm
```
</details>

<details>
<summary>Gentoo (emerge)</summary>

```sh
sudo emerge --ask dev-lang/python net-libs/libpcap net-libs/nodejs
```

The compiler and `make` are part of the base system.
</details>

<details>
<summary>Alpine (apk)</summary>

```sh
sudo apk add build-base linux-headers python3 libpcap nodejs npm
```
</details>

<details>
<summary>macOS</summary>

```sh
xcode-select --install
brew install node
```

The Xcode command line tools supply the compiler, `make` and `python3`. macOS includes `libpcap`.
</details>

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

The install gets the masscan sources and compiles them with `make` and `gcc`. Install the packages in [Requirements](#requirements) first, or the build fails. You do not need to fetch the submodule yourself.

## Run without root

Masscan sends raw packets, so a scan needs root: `sudo node your-script.js`.

On Linux, you can give the Node.js binary the raw-socket capability one time. After that, scans work as an ordinary user:

```sh
sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v node)")"
```

`readlink -f` is necessary because `node` is often a symbolic link, and `setcap` accepts only a regular file. The capability applies to every script that this `node` binary runs. Run the command again after a Node.js update. To remove the capability, use `sudo setcap -r` with the same path. macOS has no such capability, so use `sudo` there.

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

masscan.scan(opts).done
  .then((report) => console.log(JSON.stringify(report, null, 2)))
  .catch((err) => console.error(err.message));
```

Options are masscan settings, named in camelCase. For example, `excludePorts` sets masscan's `exclude-ports`. `verbose` (0 to 10) sets the log level, and `collect: false` keeps results out of the final report. A process runs one scan at a time.

The example prints one JSON report. `hosts` has one entry for each address, with its open ports. `results` has one entry for each port. The same code is in `examples/basic.js`.

`examples/advanced.js` finds the interfaces that have an address, scans from each one, and prints the open ports for each address. It needs no changes before the first run:

```sh
sudo node examples/advanced.js
```

Scan only networks that you own or have permission to scan.

## Credits

[masscan](https://github.com/robertdavidgraham/masscan) is the work of Robert David Graham and its contributors.

## License

This software is licensed under the [AGPL-3.0](LICENSE).

Copyright Jason Gerfen, 2019.

