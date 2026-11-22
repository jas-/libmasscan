'use strict';

// Prints each open port and banner as masscan finds it, instead of one report at the end.
// Change `range` to a network that you may scan, then run it as root:
//
//   sudo node examples/stream.js
//
// Ctrl+C stops the scan and prints where it stopped.

const masscan = require('..'); // in your project: require('libmasscan')

const scan = masscan.scan({
  ports: '22,80,443,8080',
  range: '192.168.1.0/24',
  banners: true,
});

process.once('SIGINT', () => scan.stop({ force: true }));

(async () => {
  let open = 0;
  for await (const event of scan) {
    if (event.type === 'result' && event.status === 'open') {
      open++;
      console.log(`open    ${event.ip}:${event.port}/${event.protocol}`);
    } else if (event.type === 'banner') {
      console.log(`banner  ${event.ip}:${event.port} ${event.service}: ${JSON.stringify(event.banner)}`);
    }
  }
  const report = await scan.done;
  console.log(`${open} open ports in ${report.durationMs} ms`);
  if (report.resumeIndex !== null) console.log(`stopped at index ${report.resumeIndex}`);
})().catch((err) => {
  console.error(err.message);
  process.exitCode = 1;
});
