'use strict';

/**
 * SQLite 封装（better-sqlite3 v11，兼容 Node 20/22）。
 * - schema 初始化（幂等 migrate）
 * - WAL 模式，NORMAL synchronous（性能优先，崩溃最多丢最近提交）
 * - 容量清理：connections / samples / logs 保留期控制
 */

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'z-proxy.db');

// 保留期（ms）
const CONN_KEEP_MS = 30 * 24 * 3600 * 1000;   // connections 30 天
const SAMPLE_KEEP_MS = 30 * 24 * 3600 * 1000; // samples 30 天
const LOG_MAX_ROWS = 50000;                    // logs 最多 5 万条

let db = null;

function init() {
  if (db) return db;
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  migrate();
  return db;
}

function migrate() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS connections (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id  TEXT,
      proto      TEXT NOT NULL,
      target     TEXT NOT NULL,
      host       TEXT,
      port       INTEGER,
      ip         TEXT,
      started_at INTEGER NOT NULL,
      ended_at   INTEGER,
      bytes_up   INTEGER DEFAULT 0,
      bytes_down INTEGER DEFAULT 0,
      status     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_conn_started ON connections(started_at);
    CREATE INDEX IF NOT EXISTS idx_conn_status  ON connections(status);
    CREATE INDEX IF NOT EXISTS idx_conn_ended   ON connections(ended_at);

    CREATE TABLE IF NOT EXISTS samples (
      ts         INTEGER PRIMARY KEY,
      bytes_up   INTEGER NOT NULL,
      bytes_down INTEGER NOT NULL,
      active     INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

    CREATE TABLE IF NOT EXISTS logs (
      id    INTEGER PRIMARY KEY AUTOINCREMENT,
      ts    INTEGER NOT NULL,
      level TEXT NOT NULL,
      msg   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at INTEGER
    );
  `);
}

function cleanup() {
  if (!db) return;
  const now = Date.now();
  db.prepare('DELETE FROM connections WHERE ended_at IS NOT NULL AND ended_at < ?').run(now - CONN_KEEP_MS);
  db.prepare('DELETE FROM samples WHERE ts < ?').run(now - SAMPLE_KEEP_MS);
  db.prepare('DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?').run(LOG_MAX_ROWS);
}

function get() {
  if (!db) init();
  return db;
}

function close() {
  if (db) db.close();
  db = null;
}

module.exports = { init, get, cleanup, close, DB_PATH, DATA_DIR };
