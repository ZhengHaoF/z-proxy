// 与 server/admin_server.js 的 REST API 对应的类型定义

export interface Status {
  startedAt: number
  uptimeMs: number
  activeConns: number
  totalConns: number
  totalBytesUp: number
  totalBytesDown: number
  dayBytesUp: number
  dayBytesDown: number
  dayStart: number
  denied: { '400': number; '407': number; '502': number }
  now: number
  todayConns: number
  server: { version: string; node: string; pid: number; pm2: string | null }
}

export interface ActiveConn {
  id: number
  client_id: string | null
  proto: 'CONNECT' | 'HTTP'
  target: string
  host: string | null
  port: number | null
  ip: string | null
  startedAt: number
  up: number
  down: number
}

export interface TrafficPoint {
  ts: number
  up: number
  down: number
  active: number
}

export interface LogEntry {
  id: number
  ts: number
  level: 'info' | 'warn' | 'error'
  msg: string
}

export interface AdminConfig {
  forward: {
    port: number
    host: string
    idleTimeoutSec: number
    tokenSet: boolean
  }
  admin: {
    port: number
    host: string
    passwordSet: boolean
    tokenTtlHours: number
  }
  db: { path: string; journal: string }
  node: string
}
