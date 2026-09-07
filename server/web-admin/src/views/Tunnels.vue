<script setup lang="ts">
import { h, onBeforeUnmount, onMounted, ref } from 'vue'
import { NDataTable, NButton, NSpace, NTag, NText, useMessage, type DataTableColumns } from 'naive-ui'
import { apiActiveConns, apiCloseConn, type ActiveConn } from '../api/client'
import { fmtBytes, fmtDuration } from '../utils/format'

const message = useMessage()
const rows = ref<ActiveConn[]>([])
const loading = ref(false)
let timer: number | null = null

async function refresh() {
  try { rows.value = await apiActiveConns() } catch (_) {}
}

async function closeConn(id: number) {
  try {
    await apiCloseConn(id)
    message.success(`已断开连接 #${id}`)
    setTimeout(refresh, 300)
  } catch (e: any) {
    message.error(e?.response?.data?.error || '断开失败')
  }
}

const columns: DataTableColumns<ActiveConn> = [
  { title: 'ID', key: 'id', width: 60 },
  {
    title: '客户端', key: 'client_id', width: 120,
    render: (r) => (r.client_id
      ? h(NTag, { size: 'small', type: 'info' }, { default: () => r.client_id })
      : h(NText, { depth: 3 }, { default: () => '未知' })),
  },
  {
    title: '协议', key: 'proto', width: 90,
    render: (r) => h(NTag, { size: 'small', type: r.proto === 'CONNECT' ? 'warning' : 'default' }, { default: () => r.proto }),
  },
  { title: '目标', key: 'target' },
  { title: '出口 IP', key: 'ip', width: 130, render: (r) => r.ip || '-' },
  {
    title: '已建立', key: 'startedAt', width: 110,
    render: (r) => fmtDuration(Date.now() - r.startedAt),
  },
  { title: '上行', key: 'up', width: 90, render: (r) => fmtBytes(r.up) },
  { title: '下行', key: 'down', width: 90, render: (r) => fmtBytes(r.down) },
  {
    title: '操作', key: 'action', width: 90,
    render: (r) => h(
      NButton, { size: 'tiny', type: 'error', quaternary: true, onClick: () => closeConn(r.id) },
      { default: () => '断开' },
    ),
  },
]

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<template>
  <n-space vertical :size="12">
    <n-text depth="3" style="font-size: 12px">当前活跃隧道（每 5 秒自动刷新）</n-text>
    <n-data-table
      :columns="columns"
      :data="rows"
      :loading="loading"
      :row-key="(r: ActiveConn) => r.id"
      :max-height="560"
      size="small"
    />
  </n-space>
</template>
