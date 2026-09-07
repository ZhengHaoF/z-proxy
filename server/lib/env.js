'use strict';

/**
 * .env 加载器（零依赖，兼容 pm2 / 前台 / --env-file 缺席场景）。
 *
 * 规则：
 * - 解析 server/.env（KEY=VALUE，支持 # 注释、空行、引号）
 * - 合并进 process.env，**真实环境变量优先**（不覆盖已存在的键）
 * - 幂等：多次调用只加载一次
 *
 * 必须在 server.js 读取任何 process.env 之前 require 本模块并调用 load()。
 */

const fs = require('fs');
const path = require('path');

const ENV_PATH = process.env.ENV_FILE || path.join(__dirname, '..', '.env');
let loaded = false;

function parse(content) {
  const env = {};
  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#') || !t.includes('=')) continue;
    const i = t.indexOf('=');
    const k = t.slice(0, i).trim();
    let v = t.slice(i + 1).trim();
    // 去掉包裹的引号
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    if (k) env[k] = v;
  }
  return env;
}

function load() {
  if (loaded) return;
  loaded = true;
  if (!fs.existsSync(ENV_PATH)) return;
  try {
    const env = parse(fs.readFileSync(ENV_PATH, 'utf8'));
    for (const [k, v] of Object.entries(env)) {
      // 真实环境变量优先，.env 只填充缺失项
      if (process.env[k] === undefined) process.env[k] = v;
    }
  } catch (_) { /* 解析失败静默忽略，走环境变量/默认值 */ }
}

module.exports = { load, parse, ENV_PATH };
