// axios 封装：统一 /api 前缀 + Bearer token + 401 跳登录
import axios from 'axios'
import type { AdminConfig, ActiveConn, LogEntry, Status, TrafficPoint } from './types'

export type { AdminConfig, ActiveConn, LogEntry, Status, TrafficPoint }

const TOKEN_KEY = 'admin_token'

export const client = axios.create({ baseURL: '/api', timeout: 15000 })

client.interceptors.request.use((cfg) => {
  const t = localStorage.getItem(TOKEN_KEY)
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

client.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      if (window.location.pathname !== '/login') window.location.href = '/login'
    }
    return Promise.reject(err)
  },
)

export async function apiLogin(password: string): Promise<string> {
  const { data } = await client.post<{ token: string }>('/login', { password })
  return data.token
}

export async function apiStatus(): Promise<Status> {
  const { data } = await client.get<Status>('/status')
  return data
}

export async function apiActiveConns(): Promise<ActiveConn[]> {
  const { data } = await client.get<{ connections: ActiveConn[] }>('/connections')
  return data.connections
}

export async function apiTraffic(range: '1h' | '24h' | '7d'): Promise<TrafficPoint[]> {
  const { data } = await client.get<{ points: TrafficPoint[] }>('/traffic', { params: { range } })
  return data.points
}

export async function apiLogs(limit = 200, level?: string): Promise<LogEntry[]> {
  const { data } = await client.get<{ logs: LogEntry[] }>('/logs', { params: { limit, level } })
  return data.logs
}

export async function apiConfig(): Promise<AdminConfig> {
  const { data } = await client.get<AdminConfig>('/config')
  return data
}

export async function apiCloseConn(id: number): Promise<void> {
  await client.post(`/connections/${id}/close`)
}

export function streamUrl(token: string): string {
  return `${window.location.origin}/api/stream?token=${encodeURIComponent(token)}`
}
