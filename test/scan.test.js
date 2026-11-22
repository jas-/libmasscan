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

function scanLog(options) {
  const scan = masscan.scan({ ...OFFLINE, rate: 100000, wait: 0, ...options });
  const logs = [];
  scan.on('log', (l) => logs.push(l));
  return scan.done.then((report) => ({ report, logs }));
}

test('options become masscan settings', async () => {
  const { logs } = await scanLog({
    range: ['10.0.0.0/30', '10.0.1.0/30'],
    ports: '80-90',
    excludePorts: '85',
    openOnly: false,
    verbose: 1,
  });
  assert.ok(logs.some((l) => /Scanning 8 hosts \[10 ports\/host\]/.test(l.message)));
  assert.ok(logs.some((l) => l.level === 1), 'verbose: 1 gives level 1 log events');
});

test('the original option names still work', async () => {
  const { adapter, ...rest } = OFFLINE;
  const scan = masscan.scan({ ...rest, iface: adapter, range: '10.0.0.0/30', ports: '80-90', excludeports: '85', wait: 0 });
  const logs = [];
  scan.on('log', (l) => logs.push(l.message));
  await scan.done;
  assert.ok(logs.some((m) => /Scanning 4 hosts \[10 ports\/host\]/.test(m)));
});

test('bad options throw a TypeError before the scan starts', () => {
  assert.throws(() => masscan.scan('x'), TypeError);
  assert.throws(() => masscan.scan(null), TypeError);
  assert.throws(() => masscan.scan({ 'bad name': 1 }), TypeError);
  assert.throws(() => masscan.scan({ range: [{}] }), TypeError);
  assert.throws(() => masscan.scan({ verbose: -1 }), TypeError);
  assert.equal(masscan.isRunning(), false);
});

test('the module has no command-line interface', async () => {
  assert.equal(masscan.toArgs, undefined);
  await assert.rejects(masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', args: ['--ttl', '64'] }).done,
    /unknown config option: args/);
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
    ['startedAt', 'finishedAt', 'durationMs', 'resumeIndex', 'counts', 'results', 'hosts', 'banners']);
  assert.deepEqual(report.counts, { results: 0, open: 0, closed: 0, banners: 0 });
  assert.deepEqual(report.results, []);
  assert.deepEqual(report.hosts, []);
  assert.ok(!Number.isNaN(Date.parse(report.startedAt)));
  assert.ok(Date.parse(report.finishedAt) >= Date.parse(report.startedAt));
  assert.ok(report.durationMs >= 0);
  // The report survives a JSON round trip without change.
  assert.deepEqual(JSON.parse(JSON.stringify(report)), report);
});

test('report.hosts groups the open ports of each address', async () => {
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 });
  const result = (ip, port, status = 'open') => ({ type: 'result', ip, port, protocol: 'tcp', status });
  scan._dispatch([
    result('10.0.0.2', 8080),
    result('10.0.0.1', 443),
    result('10.0.0.2', 80),
    result('10.0.0.2', 80),
    result('10.0.0.3', 22, 'closed'),
  ]);
  const report = await scan.done;

  assert.equal(report.results.length, 5);
  assert.deepEqual(report.hosts, [
    { ip: '10.0.0.2', ports: [{ port: 80, protocol: 'tcp' }, { port: 8080, protocol: 'tcp' }] },
    { ip: '10.0.0.1', ports: [{ port: 443, protocol: 'tcp' }] },
  ]);
});

test('collect is not passed to masscan', async () => {
  const { report } = await scanLog({ range: '10.0.0.0/30', ports: '80', collect: false });
  assert.deepEqual(report.results, []);
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

test('for await yields result and banner events, then ends with the scan', async () => {
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/30', ports: '80', wait: 0 });
  const seen = [];
  const loop = (async () => {
    for await (const event of scan) seen.push(event);
  })();
  scan._dispatch([
    { type: 'result', ip: '10.0.0.1', port: 80, protocol: 'tcp', status: 'open' },
    { type: 'progress', percent: 50 },
    { type: 'banner', ip: '10.0.0.1', port: 80, protocol: 'tcp', service: 'http', banner: 'x' },
    { type: 'log', level: 0, message: 'not yielded' },
  ]);
  await loop;
  assert.deepEqual(seen.map((e) => [e.type, e.ip]), [['result', '10.0.0.1'], ['banner', '10.0.0.1']]);
  assert.equal(seen[0].status, 'open');
  assert.equal(seen[1].service, 'http');
  assert.equal(scan.listenerCount('result'), 0, 'the loop removes its listeners');
});

test('for await throws the scan error', async () => {
  const scan = masscan.scan({ ports: '80' });
  await assert.rejects(async () => {
    for await (const event of scan) assert.fail(`unexpected ${event.type}`);
  }, (err) => err.code === 'ERR_MASSCAN_SCAN' && /target IP address list empty/.test(err.message));
});

test('a break in for await stops the scan', async () => {
  // 65536 targets at 1000 packets/second takes about 65 seconds.
  const scan = masscan.scan({ ...OFFLINE, range: '10.0.0.0/16', ports: '80', rate: 1000, wait: 30 });
  const started = Date.now();
  setTimeout(() => scan._dispatch([{ type: 'result', ip: '10.0.0.1', port: 80, protocol: 'tcp', status: 'open' }]), 500);
  for await (const event of scan) {
    assert.equal(event.type, 'result');
    break;
  }
  assert.equal(scan.running, false);
  assert.equal(masscan.isRunning(), false);
  assert.ok(Date.now() - started < 10000, 'stop took too long');
  assert.equal(typeof (await scan.done).resumeIndex, 'number');
});

test('a failed scan read with for await is not an unhandled rejection', () => {
  const r = child(`
    (async () => {
      try { for await (const e of masscan.scan({ ports: '80' })); } catch (err) { console.log('caught'); }
    })();
  `);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /caught/);
});
