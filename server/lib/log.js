'use strict';

/**
 * 日志统一出口：拦截 console.log/warn/error，
 * 原样输出 + 内存环形缓冲（SSE 实时广播）+ 50ms 攒批写库（WAL）。
 * 写库失败静默降级，绝不阻断转发。
 */

const EventEmitter = require('events');
const db = require('../db');

const MAX_BUFFER = 2000;   // 内存环形缓冲上限
const FLUSH_MS = 50;       // 攒批间隔

const bus = new EventEmitter();
let buffer = [];
let timer = null;
let installed = false;

function fmt(x) {
  if (typeof x === 'string') return x;
  if (x instanceof Error) return x.stack || x.message;
  try { return JSON.stringify(x); } catch (_) { return String(x); }
}

function record(level, args) {
  const msg = args.map(fmt).join(' ');
  const entry = { ts: Date.now(), level, msg };
  buffer.push(entry);
  if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
  bus.emit('log', entry);
  scheduleFlush();
}

function scheduleFlush() {
  if (timer) return;
  timer = setTimeout(flush, FLUSH_MS);
}

function flush() {
  if (timer) clearTimeout(timer);
  timer = null;
  if (!buffer.length) return;
  const rows = buffer.splice(0);
  try {
    const d = db.get();
    const ins = d.prepare('INSERT INTO logs (ts, level, msg) VALUES (?, ?, ?)');
    const tx = d.transaction((r) => { for (const x of r) ins.run(x.ts, x.level, x.msg); });
    tx(rows);
  } catch (_) { /* 写库失败静默降级 */ }
}

/** 拦截 console（幂等），须在业务代码最早处 require */
function install() {
  if (installed) return;
  installed = true;
  const orig = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
  };
  console.log = (...a) => { orig.log(...a); record('info', a); };
  console.warn = (...a) => { orig.warn(...a); record('warn', a); };
  console.error = (...a) => { orig.error(...a); record('error', a); };
}

/** 查询最近日志（写库失败时退化为内存缓冲） */
function getRecent(limit = 200, level) {
  limit = Math.max(1, Math.min(limit, 2000));
  try {
    const d = db.get();
    const lv = level ? d.prepare('SELECT * FROM logs WHERE level = ? ORDER BY id DESC LIMIT ?') : d.prepare('SELECT * FROM logs ORDER BY id DESC LIMIT ?');
    const records = level ? lv.all(level, limit) : lv.all(limit);
    const rows = records.map((r) => ({ id: r.id, ts: r.ts, level: r.level, msg: r.msg }));
    if (level) rows.splice(limit);
    return rows.reverse();
  } catch (_) {
    return buffer.slice(-limit).map((e) => ({ id: -1, ...e }));
  }
}

module.exports = { install, bus, getRecent, flush };
