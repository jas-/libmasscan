'use strict';

// --offline runs the full scan without packets, so no root is needed.

const test = require('node:test');
const assert = require('node:assert/strict');
const masscan = require('..');

// Offline mode does not look up adapter settings.
const OFFLINE = {
  offline: true,
  adapter: process.platform === 'darwin' ? 'lo0' : 'lo',
  adapterIp: '10.9.9.9',
  adapterMac: '00-11-22-33-44-55',
  routerMac: '66-55-44-33-22-11',
};

test('toArgs maps options to masscan arguments', () => {
  assert.deepEqual(
    masscan.toArgs({
      range: ['10.0.0.0/24', '10.1.0.0/24'],
      ports: '80,443',
      excludePorts: '8080',
      banners: true,
      openOnly: false,
      rate: 1000,
      verbose: 2,
      args: ['--ttl', '64'],
    }),
    [
      '--range=10.0.0.0/24',
      '--range=10.1.0.0/24',
      '--ports=80,443',
      '--exclude-ports=8080',
      '--banners=true',
      '--rate=1000',
      '-vv',
      '--ttl',
      '64',
    ],
  );
});

test('toArgs keeps the original option names', () => {
  assert.deepEqual(
    masscan.toArgs({ iface: 'eth0', excludeports: '9000-9999' }),
    ['--adapter=eth0', '--exclude-ports=9000-9999'],
  );
});

test('toArgs rejects bad input', () => {
  assert.throws(() => masscan.toArgs('x'), TypeError);
  assert.throws(() => masscan.toArgs({ 'bad name': 1 }), TypeError);
  assert.throws(() => masscan.toArgs({ range: [{}] }), TypeError);
  assert.throws(() => masscan.toArgs({ args: [1] }), TypeError);
  assert.throws(() => masscan.toArgs({ verbose: -1 }), TypeError);
});

test('an unknown option rejects without ending the process', async () => {
  const scan = masscan.scan({ range: '10.0.0.0/30', ports: '80', notAnOption: 1 });
  await assert.rejects(scan.done, (err) => {
    assert.equal(err.code, 'ERR_MASSCAN_SCAN');
    assert.match(err.message, /unknown config option: not-an-option/);
    return true;
  });
  assert.equal(masscan.isRunning(), false);
});

test('a scan with no ports rejects', async () => {
  await assert.rejects(masscan.scan({ range: '10.0.0.0/30' }).done,
    /no ports were specified/);
});

test('a scan with no targets rejects', async () => {
  await assert.rejects(masscan.scan({ ports: '80' }).done,
    /target IP address list empty/);
});

test('a scan of more than 1e9 addresses needs an exclude', async () => {
  await assert.rejects(masscan.scan({ range: '0.0.0.0/0', ports: '80' }).done,
    /range too big/);
});

test('excludes that remove every target reject', async () => {
  await assert.rejects(
    masscan.scan({ range: '10.0.0.0/24', exclude: '10.0.0.0/8', ports: '80' }).done,
    /removed by exclusion/);
});

test('the error event fires when a listener exists', async () => {
  const scan = masscan.scan({ ports: '80' });
  const err = await new Promise((resolve) => scan.on('error', resolve));
  assert.match(err.message, /target IP address list empty/);
});

test('an offline scan completes and reports progress', async () => {
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/28', ports: '80,443', rate: 100000, wait: 0 });
  const progress = [];
  const logs = [];
  scan.on('progress', (p) => progress.push(p));
  scan.on('log', (l) => logs.push(l.message));

  assert.equal(masscan.isRunning(), true);
  const summary = await scan.done;

  assert.equal(summary.resumeIndex, null);
  assert.ok(progress.length > 0, 'expected progress events');
  assert.equal(progress.at(-1).total, 32);
  assert.ok(logs.some((m) => /Scanning 16 hosts \[2 ports\/host\]/.test(m)));
  assert.equal(masscan.isRunning(), false);
});

test('scan.done resolves with a JSON report', async () => {
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 });
  let emitted;
  scan.on('done', (r) => { emitted = r; });
  const report = await scan.done;

  assert.equal(emitted, report);
  assert.deepEqual(Object.keys(report),
    ['startedAt', 'finishedAt', 'durationMs', 'resumeIndex', 'counts', 'results', 'banners']);
  assert.deepEqual(report.counts, { results: 0, open: 0, closed: 0, banners: 0 });
  assert.deepEqual(report.results, []);
  assert.ok(!Number.isNaN(Date.parse(report.startedAt)));
  assert.ok(Date.parse(report.finishedAt) >= Date.parse(report.startedAt));
  assert.ok(report.durationMs >= 0);
  // The report survives a JSON round trip without change.
  assert.deepEqual(JSON.parse(JSON.stringify(report)), report);
});

test('collect is not passed to masscan', () => {
  assert.deepEqual(masscan.toArgs({ ports: '80', collect: false }), ['--ports=80']);
});

test('a second scan while one runs throws ERR_MASSCAN_BUSY', async () => {
  const first = masscan.scan({ ...OFFLINE, range: '10.0.0.0/28', ports: '80', wait: 0 });
  assert.throws(() => masscan.scan({ ...OFFLINE, range: '10.0.0.0/28', ports: '80' }),
    { code: 'ERR_MASSCAN_BUSY' });
  await first.done;
});

test('a done handler can start the next scan', async () => {
  const first = masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 });
  const second = await new Promise((resolve, reject) => {
    first.on('done', () => {
      try {
        resolve(masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 }));
      } catch (err) {
        reject(err);
      }
    });
  });
  await second.done;
});

test('stop({ force: true }) ends a long scan and returns a resume index', async () => {
  // 65536 targets at 1000 packets/second takes about 65 seconds.
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/16', ports: '80', rate: 1000, wait: 30 });
  const started = Date.now();
  await new Promise((resolve) => setTimeout(resolve, 1500));
  scan.stop({ force: true });
  const summary = await scan.done;

  assert.ok(Date.now() - started < 10000, 'stop took too long');
  assert.equal(typeof summary.resumeIndex, 'number');
  assert.ok(summary.resumeIndex > 0 && summary.resumeIndex < 65536);
});

test('many scans in a row do not leak file descriptors', async () => {
  const fs = require('node:fs');
  const fds = () => fs.readdirSync('/dev/fd').length;
  const before = fds();
  for (let i = 0; i < 20; i++) {
    await masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 }).done;
  }
  assert.ok(fds() - before < 5, `fd count grew from ${before} to ${fds()}`);
});

test('a failure that the module finds reports exit code 1', async () => {
  await assert.rejects(masscan.scan({ range: '10.0.0.0/30' }).done,
    (err) => err.exitCode === 1);
});

// These run in a child process, because they test what reaches the process.
function child(code) {
  const { spawnSync } = require('node:child_process');
  return spawnSync(process.execPath, ['-e', `const masscan = require(${JSON.stringify(require.resolve('..'))});\n${code}`],
    { encoding: 'utf8', timeout: 60_000 });
}

test('a failed scan with no error listener is an unhandled rejection', () => {
  const r = child(`masscan.scan({ ports: '80' }).on('done', () => console.log('done'));`);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /target IP address list empty/);
  assert.doesNotMatch(r.stdout, /done/);
});

test('a throwing listener reaches uncaughtException and the scan still settles', () => {
  const r = child(`
    const OFFLINE = ${JSON.stringify(OFFLINE)};
    let thrown = 0;
    process.on('uncaughtException', () => thrown++);
    const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 });
    scan.on('progress', () => { throw new Error('listener bug'); });
    scan.done.then(() => setImmediate(() => console.log('settled', thrown > 0)));
  `);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /settled true/);
});
