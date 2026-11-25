// Loaded inside the sandbox before a Node script of the skill starts
// (through NODE_OPTIONS). Records network, process and file calls to the
// trace file. It blocks nothing: the sandbox has no network and no real files.
'use strict';
const fs = require('fs');
const path = require('path');
const TRACE = process.env.SR_TRACE || '';
const WATCH = (process.env.SR_WATCH || '').split(path.delimiter).filter(Boolean);
const append = fs.appendFileSync.bind(fs);

function write(kind, fields) {
  if (!TRACE) return;
  try {
    fields.kind = kind;
    fields.pid = process.pid;
    append(TRACE, JSON.stringify(fields).slice(0, 1200) + '\n');
  } catch (error) { /* tracing must never break the script */ }
}

function watched(target) {
  if (typeof target !== 'string' && !(target instanceof URL) && !Buffer.isBuffer(target)) return '';
  let full;
  try { full = path.resolve(target instanceof URL ? target.pathname : String(target)); } catch (e) { return ''; }
  return full !== TRACE && WATCH.some((root) => full.startsWith(root)) ? full : '';
}

function wrap(owner, name, record) {
  const original = owner && owner[name];
  if (typeof original !== 'function') return;
  owner[name] = function patched(...args) {
    try { record(args); } catch (error) { /* ignore */ }
    return original.apply(this, args);
  };
}

if (TRACE) {
  const net = require('net');
  const dns = require('dns');
  const child = require('child_process');
  wrap(net.Socket.prototype, 'connect', (args) => {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0];
    const options = first && typeof first === 'object' ? first : { port: first, host: args[1] };
    if (options.path) return;
    write('net', { address: String(options.host || 'localhost') + ':' + String(options.port || '') });
  });
  wrap(dns, 'lookup', (args) => write('dns', { host: String(args[0]) }));
  if (dns.promises) wrap(dns.promises, 'lookup', (args) => write('dns', { host: String(args[0]) }));
  for (const name of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
    wrap(child, name, (args) => {
      const rest = Array.isArray(args[1]) ? args[1] : [];
      write('exec', { argv: [String(args[0]).slice(0, 200)].concat(rest.map((a) => String(a).slice(0, 200))).slice(0, 20) });
    });
  }
  for (const name of ['readFileSync', 'readFile', 'openSync', 'open', 'createReadStream']) {
    wrap(fs, name, (args) => {
      const full = watched(args[0]);
      if (full) write('open', { path: full, mode: typeof args[1] === 'string' ? args[1] : 'r' });
    });
  }
  for (const name of ['writeFileSync', 'writeFile', 'appendFile', 'createWriteStream', 'unlinkSync', 'unlink', 'rmSync', 'rm']) {
    wrap(fs, name, (args) => {
      const full = watched(args[0]);
      if (full) write('change', { op: 'fs.' + name, path: full });
    });
  }
  if (fs.promises) {
    wrap(fs.promises, 'readFile', (args) => { const full = watched(args[0]); if (full) write('open', { path: full, mode: 'r' }); });
    wrap(fs.promises, 'open', (args) => { const full = watched(args[0]); if (full) write('open', { path: full, mode: String(args[1] || 'r') }); });
  }
  if (typeof globalThis.fetch === 'function') {
    const realFetch = globalThis.fetch;
    globalThis.fetch = function patchedFetch(input, init) {
      try { write('url', { url: String(input && input.url ? input.url : input).slice(0, 300) }); } catch (e) { /* ignore */ }
      return realFetch.call(this, input, init);
    };
  }
  try { require('module').syncBuiltinESMExports(); } catch (error) { /* older Node */ }
}
