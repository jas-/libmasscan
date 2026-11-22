'use strict';

// Prints each result and banner as one JSON line when masscan finds it, instead of one report at the end.
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
  for await (const event of scan) {
    console.log(JSON.stringify(event));
  }
  const report = await scan.done;
  console.log(JSON.stringify({ counts: report.counts, durationMs: report.durationMs, resumeIndex: report.resumeIndex }));
})().catch((err) => {
  console.error(err.message);
  process.exitCode = 1;
});
