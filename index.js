'use strict';

const { EventEmitter } = require('node:events');
const binding = require('./build/Release/masscan.node');

// Option names from the original libmasscan API.
const ALIASES = {
  iface: 'adapter',
  excludeports: 'exclude-ports',
  gateway: 'router-mac',
};

const NAME = /^[a-z0-9][a-z0-9-]*$/;

function kebab(key) {
  return key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

// Converts an options object to masscan arguments. See "Options" in the README.
function toArgs(options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('options must be an object');
  }

  const args = [];
  for (const [key, value] of Object.entries(options)) {
    if (key === 'args' || key === 'verbose' || key === 'collect') continue;
    if (value === undefined || value === null || value === false) continue;

    const name = ALIASES[key] || kebab(key);
    if (!NAME.test(name)) {
      throw new TypeError(`invalid option name: ${key}`);
    }

    const values = Array.isArray(value) ? value : [value];
    for (const item of values) {
      if (typeof item === 'object' && item !== null) {
        throw new TypeError(`option ${key} must be a string, number, boolean or array of those`);
      }
      args.push(`--${name}=${item === true ? 'true' : String(item)}`);
    }
  }

  if (options.verbose) {
    const level = Number(options.verbose);
    if (!Number.isInteger(level) || level < 0 || level > 10) {
      throw new TypeError('verbose must be an integer from 0 to 10');
    }
    if (level > 0) args.push(`-${'v'.repeat(level)}`);
  }

  if (options.args !== undefined) {
    if (!Array.isArray(options.args) || !options.args.every((a) => typeof a === 'string')) {
      throw new TypeError('args must be an array of strings');
    }
    args.push(...options.args);
  }

  return args;
}

// One running scan. See "Events" in the README.
class Scan extends EventEmitter {
  constructor(args, { collect = true } = {}) {
    super();
    this.args = args;
    this.running = true;
    this.collect = collect;
    this.report = {
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      resumeIndex: null,
      counts: { results: 0, open: 0, closed: 0, banners: 0 },
      results: [],
      banners: [],
    };
    this._started = Date.now();
    this.done = new Promise((resolve, reject) => {
      this._resolve = resolve;
      this._reject = reject;
    });
    // A caller that uses only events must not get an unhandled rejection.
    this.done.catch(() => {});

    binding.start(args, (events) => this._dispatch(events));
  }

  _dispatch(events) {
    const { report } = this;
    for (const event of events) {
      const { type, ...data } = event;
      if (type === 'result') {
        report.counts.results++;
        if (data.status === 'open') report.counts.open++;
        else if (data.status === 'closed') report.counts.closed++;
        if (this.collect) report.results.push(data);
      } else if (type === 'banner') {
        report.counts.banners++;
        if (this.collect) report.banners.push(data);
      }

      if (type === 'done') {
        this._finish(data);
      } else {
        this.emit(type, data);
      }
    }
  }

  _finish({ error, exitCode, resumeIndex }) {
    this.running = false;
    const { report } = this;
    report.finishedAt = new Date().toISOString();
    report.durationMs = Date.now() - this._started;
    report.resumeIndex = resumeIndex ?? null;

    if (error) {
      const err = new Error(error);
      err.code = 'ERR_MASSCAN_SCAN';
      err.exitCode = exitCode;
      err.log = error.split('\n');
      err.report = report;
      this._reject(err);
      if (this.listenerCount('error') > 0) this.emit('error', err);
      return;
    }
    this._resolve(report);
    this.emit('done', report);
  }

  // First call: stop sending, then wait for late responses. force or a second call: stop now.
  stop({ force = false } = {}) {
    if (this.running) binding.stop(Boolean(force));
    return this.done.catch(() => {});
  }
}

// One scan per process. A second call while a scan runs throws ERR_MASSCAN_BUSY.
function scan(options = {}) {
  return new Scan(toArgs(options), { collect: options.collect !== false });
}

function isRunning() {
  return binding.isRunning();
}

module.exports = { scan, isRunning, toArgs, Scan };
