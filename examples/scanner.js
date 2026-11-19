'use strict';

// A reusable scanner module for applications. Copy it into a project, or
// require it from here.
//
//   const { Scanner } = require('libmasscan/examples/scanner');
//   const scanner = new Scanner({ rate: 5000 });
//   const report = await scanner.scan({ range: '10.0.0.0/24', ports: '22,80,443' });
//
// What it adds to the plain scan() API:
//   - A queue. A process runs one masscan scan at a time, so scan() calls
//     wait for their turn and never throw ERR_MASSCAN_BUSY.
//   - Defaults that apply to every scan (rate, wait, exclude list, ...).
//   - A time limit. A scan that runs too long stops, and the report holds
//     the resume index.
//   - The open ports grouped by host, added to the JSON report.

const masscan = require('..');

class Scanner {
  /**
   * @param {object} defaults masscan options for every scan, for example
   *   { rate: 5000, wait: 5, exclude: ['10.0.0.1'] }
   */
  constructor(defaults = {}) {
    this.defaults = defaults;
    this.queue = Promise.resolve();
  }

  /**
   * Queues one scan and resolves with its report.
   *
   * @param {object} options masscan options for this scan (range, ports, ...)
   * @param {object} [control]
   * @param {number} [control.timeoutMs] stop the scan after this time
   * @param {(r: object) => void} [control.onResult] called for each result
   * @param {(p: object) => void} [control.onProgress] called for each progress event
   * @returns {Promise<object>} the report of scan.done (startedAt, finishedAt,
   *   durationMs, resumeIndex, counts, results, banners), plus `hosts` (the open
   *   ports grouped by IP) and `timedOut`. All plain data, ready for JSON.
   */
  scan(options, control = {}) {
    const run = () => this._run({ ...this.defaults, ...options }, control);
    const result = this.queue.then(run, run);
    // The next scan waits for this one, whether it succeeds or fails.
    this.queue = result.catch(() => {});
    return result;
  }

  async _run(options, { timeoutMs, onResult, onProgress }) {
    const scan = masscan.scan(options);
    if (onResult) scan.on('result', onResult);
    if (onProgress) scan.on('progress', onProgress);

    let timedOut = false;
    let timer;
    if (timeoutMs) {
      timer = setTimeout(() => {
        timedOut = true;
        scan.stop({ force: true });
      }, timeoutMs);
    }

    let report;
    try {
      report = await scan.done;
    } finally {
      clearTimeout(timer);
    }

    // Group the open ports by host. Masscan can report a port twice.
    const hosts = {};
    for (const r of report.results) {
      if (r.status !== 'open') continue;
      const host = (hosts[r.ip] ??= { ip: r.ip, ports: [] });
      if (!host.ports.some((p) => p.port === r.port && p.protocol === r.protocol)) {
        host.ports.push({ port: r.port, protocol: r.protocol, ttl: r.ttl });
      }
    }
    for (const host of Object.values(hosts)) host.ports.sort((a, b) => a.port - b.port);

    return { ...report, timedOut, hosts };
  }
}

module.exports = { Scanner };
