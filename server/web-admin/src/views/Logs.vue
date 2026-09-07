<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  NButton, NSelect, NSpace, NTag, NScrollbar, NText, type SelectOption,
} from 'naive-ui'
import { apiLogs, streamUrl, type LogEntry } from '../api/client'
import { fmtClock } from '../utils/format'

const entries = ref<LogEntry[]>([])
const paused = ref(false)
const levelFilter = ref<'all' | LogEntry['level']>('all')
const scrollRef = ref<{ scrollTo: (opts: { top: number }) => void } | null>(null)

let es: EventSource | null = null
let lastId = 0
let pending: LogEntry[] = []
const MAX_ENTRIES = 2000

const levelOptions: SelectOption[] = [
  { label: '全部级别', value: 'all' },
  { label: 'info', value: 'info' },
  { label: 'warn', value: 'warn' },
  { label: 'error', value: 'error' },
]

const filtered = ref<LogEntry[]>([])

function push(list: LogEntry[]) {
  for (const e of list) {
    if (e.id > lastId) lastId = e.id
    if (e.id <= 0) continue
    entries.value.push(e)
  }
  if (entries.value.length > MAX_ENTRIES) {
    entries.value.splice(0, entries.value.length - MAX_ENTRIES)
  }
  applyFilter()
  scrollBottom()
}

function applyFilter() {
  filtered.value = levelFilter.value === 'all'
    ? entries.value
    : entries.value.filter((e) => e.level === levelFilter.value)
}

function scrollBottom() {
  requestAnimationFrame(() => {
    scrollRef.value?.scrollTo({ top: 1e9 })
  })
}

async function loadRecent() {
  try {
    const rows = await apiLogs(500)
    entries.value = []
    lastId = 0
    push(rows)
  } catch (_) {}
}

function connect() {
  const token = localStorage.getItem('admin_token')
  if (!token) return
  es = new EventSource(streamUrl(token))
  es.addEventListener('log', (ev: MessageEvent) => {
    const data = JSON.parse(ev.data) as LogEntry
    if (paused.value) { pending.push(data); return }
    push([data])
  })
  es.addEventListener('status', () => {}) // 忽略状态快照
  es.onopen = () => {
    if (lastId > 0) {
      apiLogs(500).then((rows) => {
        const fresh = rows.filter((r) => r.id > lastId)
        if (fresh.length) push(fresh)
      }).catch(() => {})
    }
  }
  es.onerror = () => { /* EventSource 自动重连 */ }
}

function togglePause() {
  paused.value = !paused.value
  if (!paused.value && pending.length) {
    push(pending)
    pending = []
  }
}

function clearAll() {
  entries.value = []
  filtered.value = []
  pending = []
  lastId = 0
}

watch(levelFilter, applyFilter)

onMounted(() => {
  loadRecent()
  connect()
})

onBeforeUnmount(() => {
  es?.close()
})
</script>

<template>
  <n-space vertical :size="12">
    <div style="display: flex; justify-content: space-between; align-items: center">
      <n-space :size="8" align="center">
        <n-select v-model:value="levelFilter" :options="levelOptions" size="small" style="width: 130px" />
        <n-text depth="3" style="font-size: 12px">SSE 实时推送 · 共 {{ filtered.length }} 条</n-text>
      </n-space>
      <n-space :size="8">
        <n-button size="small" @click="togglePause">{{ paused ? '继续' : '暂停' }}</n-button>
        <n-button size="small" @click="clearAll">清屏</n-button>
      </n-space>
    </div>

    <n-scrollbar ref="scrollRef" style="max-height: 640px; border: 1px solid var(--n-border-color, rgba(128,128,128,.2)); border-radius: 8px">
      <div style="padding: 8px 12px; font-family: Consolas, Menlo, monospace; font-size: 12px; line-height: 1.7">
        <div v-if="!filtered.length" style="opacity: .5">暂无日志…</div>
        <div v-for="e in filtered" :key="e.id" style="display: flex; gap: 8px; white-space: pre-wrap">
          <span style="opacity: .5; flex-shrink: 0">{{ fmtClock(e.ts) }}</span>
          <n-tag size="tiny" :type="e.level === 'error' ? 'error' : e.level === 'warn' ? 'warning' : 'info'" style="flex-shrink: 0">
            {{ e.level }}
          </n-tag>
          <span>{{ e.msg }}</span>
        </div>
      </div>
    </n-scrollbar>
  </n-space>
</template>
