'use strict';

/**
 * metrics：转发面观测层。
 * - 计数器：连接数 / 字节 / 错误 / 今日流量
 * - 活跃连接注册表（内存 Map，实时字节数）
 * - 事件总线：conn 事件（open/close/bytes）、status 快照
 * - 30s 流量采样写 samples 表（图表数据源）
 * - 连接关闭时落库 connections 表（历史会话）
 */

const EventEmitter = require('events');
const db = require('./db');

const bus = new EventEmitter();

const SAMPLE_MS = 30000;
const CLEANUP_INTERVAL = 120; // 每 120 次采样（1h）做一次 DB 容量清理

const state = {
  startedAt: Date.now(),
  totalConns: 0,          // 本次进程已鉴权连接（拒绝单独计入 denied）
  totalBytesUp: 0,
  totalBytesDown: 0,
  dayBytesUp: 0,
  dayBytesDown: 0,
  dayStart: dayStartOf(),
  denied: { '400': 0, '407': 0, '502': 0 },
  active: new Map(),      // connId -> conn 对象
  _nextId: 1,
};

function dayStartOf() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function rollDayIfNeeded() {
  const ds = dayStartOf();
  if (ds !== state.dayStart) {
    state.dayStart = ds;
    state.dayBytesUp = 0;
    state.dayBytesDown = 0;
  }
}

let timers = null;
let lastSampleUp = 0;
let lastSampleDown = 0;
let lastSampleTs = 0;

/** 启动采样与清理定时器（server.js 启动后调用一次） */
function start() {
  if (timers) return;
  timers = setInterval(onSample, SAMPLE_MS);
}

function onSample() {
  rollDayIfNeeded();
  // Global monotonic counters retain bytes even after a connection closes.
  const upDelta = state.totalBytesUp - lastSampleUp;
  const downDelta = state.totalBytesDown - lastSampleDown;
  const active = state.active.size;
  try {
    const ts = Math.max(Date.now(), lastSampleTs + 1);
    db.get().prepare('INSERT OR REPLACE INTO samples (ts, bytes_up, bytes_down, active) VALUES (?, ?, ?, ?)')
      .run(ts, upDelta, downDelta, active);
    lastSampleTs = ts;
    lastSampleUp = state.totalBytesUp;
    lastSampleDown = state.totalBytesDown;
  } catch (_) {}
  state._sampleCount = (state._sampleCount || 0) + 1;
  if (state._sampleCount % CLEANUP_INTERVAL === 0) {
    try { db.cleanup(); } catch (_) {}
  }
}

function stop() {
  if (timers) clearInterval(timers);
  timers = null;
  onSample();
}

/** 连接建立（验签通过后调用） */
function connOpen({ client_id, proto, target, host, port }) {
  const id = state._nextId++;
  const conn = {
    id, client_id: client_id || null, proto, target,
    host: host || null, port: port || null,
    ip: null,
    startedAt: Date.now(),
    up: 0, down: 0,
    _lastSampleUp: 0, _lastSampleDown: 0,
    status: 'active',
  };
  state.active.set(id, conn);
  state.totalConns += 1;
  bus.emit('conn', { action: 'open', id, client_id: conn.client_id, proto, target, host, port });
  return id;
}

/** CONNECT 模式连上真实目标后，记录实际 IP */
function connUpgraded(id, ip) {
  const c = state.active.get(id);
  if (!c) return;
  c.ip = ip;
  bus.emit('conn', { action: 'upgraded', id, ip });
}

/** 字节计数 */
function connBytes(id, up, down) {
  const c = state.active.get(id);
  if (!c) return;
  c.up += up;
  c.down += down;
  state.totalBytesUp += up;
  state.totalBytesDown += down;
  rollDayIfNeeded();
  state.dayBytesUp += up;
  state.dayBytesDown += down;
}

/** 连接结束（正常 / 拒绝 / 失败）。status: closed | denied | error */
function connClose(id, status, extra) {
  const c = state.active.get(id);
  if (!c) return;
  c.status = status;
  c.endedAt = Date.now();
  state.active.delete(id);
  try {
    db.get().prepare(
      `INSERT INTO connections (client_id, proto, target, host, port, ip, started_at, ended_at, bytes_up, bytes_down, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(c.client_id, c.proto, c.target, c.host, c.port, c.ip, c.startedAt, c.endedAt, c.up, c.down, status);
  } catch (_) {}
  bus.emit('conn', { action: 'close', id, status, up: c.up, down: c.down, target: c.target, client_id: c.client_id, ...(extra || {}) });
}

/** 鉴权/请求拒绝计数 */
function deny(code) {
  const k = String(code);
  if (k in state.denied) state.denied[k] += 1;
  bus.emit('conn', { action: 'deny', code });
}

/** 总览快照 */
function snapshot() {
  rollDayIfNeeded();
  let activeUp = 0;
  let activeDown = 0;
  for (const c of state.active.values()) { activeUp += c.up; activeDown += c.down; }
  return {
    startedAt: state.startedAt,
    uptimeMs: Date.now() - state.startedAt,
    activeConns: state.active.size,
    totalConns: state.totalConns,
    totalBytesUp: state.totalBytesUp,
    totalBytesDown: state.totalBytesDown,
    dayBytesUp: state.dayBytesUp,
    dayBytesDown: state.dayBytesDown,
    dayStart: state.dayStart,
    denied: { ...state.denied },
    now: Date.now(),
  };
}

/** 活跃连接列表（倒序） */
function activeList() {
  const out = [];
  for (const c of state.active.values()) {
    out.push({
      id: c.id, client_id: c.client_id, proto: c.proto, target: c.target,
      host: c.host, port: c.port, ip: c.ip,
      startedAt: c.startedAt, up: c.up, down: c.down,
    });
  }
  out.sort((a, b) => b.startedAt - a.startedAt);
  return out;
}

/** 强制断开活跃连接（返回 false 表示不存在） */
function markClosing(id) {
  const c = state.active.get(id);
  if (!c) return false;
  state.active.delete(id);
  return true;
}

module.exports = { bus, start, stop, onSample, connOpen, connUpgraded, connBytes, connClose, deny, snapshot, activeList, markClosing };
