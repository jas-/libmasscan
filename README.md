# libmasscan
Native extension provding an interface to the [masscan](https://github.com/robertdavidgraham/masscan) tool from node.js

Not quite fit for consumption.

## Install
It is not currently deployed to the `npm` registry so for now you must clone
and include submodules like so:

```sh
%> git clone --recursive https://github.com/jas-/libmasscan.git
```

## Configuration
Next you will need to change into the newly cloned folder and build.

```sh
%> cd libmasscan/
%> npm install
```

## Linking
I have not implemented the necessary functionality to copy the resulting
shared object created from the `masscan` tool into the system library folder
so for now you must resolve dependencies like so

```sh
%> export LD_LIBRARY_PATH=/path/to/libmasscan/build/Release
```

## Example use
```javascript
var lib = require('../build/Release/masscan.node')
  , opts = {
      iface: 'eth0',
      ports: '22,80,443,3306-10000',
      excludeports: '9000-9999',
      range: [
        '10.0.2.0/24',
        '192.168.2.0/25',
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
```
