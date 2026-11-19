// A separate project that imports libmasscan as a module and checks that it
// works. It takes no command-line arguments. It reads config.json, next to
// this file, and passes `options` to libmasscan's scan() unchanged.
//
//   cd examples/consumer
//   npm install
//   npm start          # config.json as shipped: offline, no root, no packets
//
// For a live scan, copy config.live.example.json to config.json, edit it,
// and run `sudo npm start`.
//
// config.json:
//   {
//     "options":   { ...libmasscan options: range, exclude, ports, rate, ... },
//     "timeoutMs": 60000   (optional: stop the scan after this time)
//   }
//
// Every key in `options` is a libmasscan option: a camelCase masscan option
// name (excludePorts -> --exclude-ports). See the Options section of the
// README. Masscan rejects an unknown option, and the scan then fails.
//
// The JSON report goes to stdout. The check lines go to stderr. The exit
// code is 0 when every check passes.

import { readFileSync } from 'node:fs';
import masscan, { scan, isRunning, toArgs } from 'libmasscan';

const CONFIG = new URL('./config.json', import.meta.url);
const TOP_LEVEL = new Set(['$comment', 'options', 'timeoutMs']);

function loadConfig() {
  let config;
  try {
    config = JSON.parse(readFileSync(CONFIG, 'utf8'));
  } catch (err) {
    throw new Error(`cannot read ${CONFIG.pathname}: ${err.message}`);
  }
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('config.json must hold a JSON object');
  }
  const unknown = Object.keys(config).filter((k) => !TOP_LEVEL.has(k));
  if (unknown.length) {
    throw new Error(`unknown key(s) in config.json: ${unknown.join(', ')}. `
      + 'Put libmasscan options inside "options".');
  }
  const { options, timeoutMs } = config;
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new Error('config.json: "options" must be an object of libmasscan options');
  }
  if (timeoutMs !== undefined && !(Number.isFinite(timeoutMs) && timeoutMs > 0)) {
    throw new Error('config.json: "timeoutMs" must be a number greater than 0');
  }
  toArgs(options); // throws a TypeError for a value that is not a string, number, boolean or array
  return { options, timeoutMs };
}

let failures = 0;
function check(name, ok) {
  console.error(`${ok ? 'ok  ' : 'FAIL'} ${name}`);
  if (!ok) failures++;
}

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(`config error: ${err.message}`);
  process.exit(2);
}
console.error(`masscan arguments: ${toArgs(config.options).join(' ')}`);

check('default and named imports are the same API', masscan.scan === scan && typeof isRunning === 'function');

const job = scan(config.options);
let lastProgress = null;
job.on('progress', (p) => { lastProgress = p; });
check('a scan runs', isRunning());

let timedOut = false;
const timer = config.timeoutMs && setTimeout(() => {
  timedOut = true;
  job.stop({ force: true });
}, config.timeoutMs);

try {
  const report = await job.done;
  check('scan.done resolves with a report', Array.isArray(report.results) && typeof report.counts === 'object');
  check('the report is valid JSON', JSON.stringify(JSON.parse(JSON.stringify(report))) === JSON.stringify(report));
  check('masscan planned probes', lastProgress !== null && lastProgress.total > 0);
  check('the scan is no longer running', !isRunning());
  if (timedOut) console.error(`stopped by timeoutMs; resume with "resumeIndex": ${report.resumeIndex}`);
  console.log(JSON.stringify({ ...report, timedOut }, null, 2));
} catch (err) {
  check(`scan.done resolves (${err.message})`, false);
} finally {
  clearTimeout(timer);
}

console.error(failures === 0 ? 'all checks passed' : `${failures} check(s) failed`);
process.exitCode = failures === 0 ? 0 : 1;
