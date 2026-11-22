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

// Converts options to masscan setting names and values, as a flat [name, value, ...] list.
function toParams(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('options must be an object');
  }

  const params = [];
  for (const [key, value] of Object.entries(options)) {
    if (key === 'verbose' || key === 'collect') continue;
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
      params.push(name, item === true ? 'true' : String(item));
    }
  }
  return params;
}

function toVerbosity(verbose = 0) {
  const level = Number(verbose);
  if (!Number.isInteger(level) || level < 0 || level > 10) {
    throw new TypeError('verbose must be an integer from 0 to 10');
  }
  return level;
}

// One running scan. Create it with scan().
class Scan extends EventEmitter {
  constructor(options = {}) {
    const params = toParams(options);
    const verbosity = toVerbosity(options.verbose);
    super();
    this.running = true;
    this.collect = options.collect !== false;
    this.report = {
      startedAt: new Date().toISOString(),
      finishedAt: null,
      durationMs: null,
      resumeIndex: null,
      counts: { results: 0, open: 0, closed: 0, banners: 0 },
      results: [],
      hosts: [],
      banners: [],
    };
    this._hosts = new Map();
    this._started = Date.now();
    this.done = new Promise((resolve, reject) => {
      this._resolve = resolve;
      this._reject = reject;
    });

    binding.start(params, verbosity, (events) => this._dispatch(events));
  }

  _dispatch(events) {
    const { report } = this;
    const thrown = [];
    for (const event of events) {
      const { type, ...data } = event;
      if (type === 'result') {
        report.counts.results++;
        if (data.status === 'open') report.counts.open++;
        else if (data.status === 'closed') report.counts.closed++;
        if (this.collect) {
          report.results.push(data);
          if (data.status === 'open') this._addHost(data);
        }
      } else if (type === 'banner') {
        report.counts.banners++;
        if (this.collect) report.banners.push(data);
      }

      // A throwing listener must not drop the rest of the batch, or the scan never settles.
      try {
        if (type === 'done') this._finish(data);
        else this.emit(type, data);
      } catch (err) {
        thrown.push(err);
      }
    }
    // Node-API hides exceptions thrown in this callback, so rethrow them outside it.
    for (const err of thrown) process.nextTick(() => { throw err; });
  }

  // Groups the open ports of one address into one report.hosts entry.
  _addHost({ ip, port, protocol }) {
    let host = this._hosts.get(ip);
    if (!host) {
      host = { ip, ports: [] };
      this._hosts.set(ip, host);
      this.report.hosts.push(host);
    }
    if (!host.ports.some((p) => p.port === port && p.protocol === protocol)) {
      host.ports.push({ port, protocol });
    }
  }

  _finish({ error, exitCode, resumeIndex }) {
    this.running = false;
    const { report } = this;
    for (const host of report.hosts) host.ports.sort((a, b) => a.port - b.port);
    report.finishedAt = new Date().toISOString();
    report.durationMs = Date.now() - this._started;
    report.resumeIndex = resumeIndex ?? null;

    if (error) {
      const err = new Error(error);
      err.code = 'ERR_MASSCAN_SCAN';
      err.exitCode = exitCode;
      err.log = error.split('\n');
      err.report = report;
      // No 'error' listener: the rejection is unhandled unless the caller uses scan.done.
      const listened = this.listenerCount('error') > 0;
      if (listened) this.done.catch(() => {});
      this._reject(err);
      if (listened) this.emit('error', err);
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

  // for await (const event of scan): yields each result and banner event as it arrives,
  // with its type. The loop ends when the scan ends, and throws if the scan fails.
  // A break, return or throw in the loop stops the scan at once.
  // Masscan does not wait for a slow loop, so events that are not read yet are kept in memory.
  [Symbol.asyncIterator]() {
    const queue = [];
    let head = 0;
    let waiting = null;
    let finished = false;
    let failure = null;

    const deliver = (item) => {
      if (waiting) {
        const { resolve } = waiting;
        waiting = null;
        resolve({ value: item, done: false });
      } else {
        queue.push(item);
      }
    };
    const onResult = (data) => deliver({ type: 'result', ...data });
    const onBanner = (data) => deliver({ type: 'banner', ...data });
    this.on('result', onResult);
    this.on('banner', onBanner);

    const detach = () => {
      this.off('result', onResult);
      this.off('banner', onBanner);
    };
    // The loop gets the scan error, so scan.done does not also report it as unhandled.
    const settle = (err) => {
      if (finished) return;
      finished = true;
      failure = err;
      detach();
      if (waiting) {
        const { resolve, reject } = waiting;
        waiting = null;
        failure = null;
        if (err) reject(err);
        else resolve({ value: undefined, done: true });
      }
    };
    this.done.then(() => settle(null), settle);

    return {
      next: () => {
        if (head < queue.length) {
          const value = queue[head];
          queue[head++] = undefined;
          if (head > 1024 && head * 2 > queue.length) {
            queue.splice(0, head);
            head = 0;
          }
          return Promise.resolve({ value, done: false });
        }
        if (finished) {
          const err = failure;
          failure = null;
          return err ? Promise.reject(err) : Promise.resolve({ value: undefined, done: true });
        }
        return new Promise((resolve, reject) => { waiting = { resolve, reject }; });
      },
      return: async () => {
        const wasRunning = !finished;
        finished = true;
        failure = null;
        queue.length = 0;
        head = 0;
        detach();
        if (wasRunning) await this.stop({ force: true });
        return { value: undefined, done: true };
      },
      [Symbol.asyncIterator]() { return this; },
    };
  }
}

// One scan per process. A second call while a scan runs throws ERR_MASSCAN_BUSY.
function scan(options = {}) {
  return new Scan(options);
}

function isRunning() {
  return binding.isRunning();
}

module.exports = { scan, isRunning, Scan };
