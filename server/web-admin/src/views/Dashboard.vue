<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { NGrid, NGi, NCard, NStatistic, NRadioGroup, NRadioButton, NSpace, NText, useMessage } from 'naive-ui'
import * as echarts from 'echarts'
import { apiStatus, apiTraffic, type Status, type TrafficPoint } from '../api/client'
import { fmtBytes, fmtRate, fmtUptime } from '../utils/format'
import { useECharts } from '../composables/useECharts'

const message = useMessage()
const status = ref<Status | null>(null)
const range = ref<'1h' | '24h' | '7d'>('24h')
const chartEl = ref<HTMLElement | null>(null)
const { setOption } = useECharts(chartEl)
let timer: number | null = null

const uptime = computed(() => (status.value ? fmtUptime(status.value.uptimeMs) : '-'))
const activeConns = computed(() => status.value?.activeConns ?? 0)
const totalBytes = computed(() => fmtBytes((status.value?.totalBytesUp ?? 0) + (status.value?.totalBytesDown ?? 0)))
const todayBytes = computed(() => fmtBytes((status.value?.dayBytesUp ?? 0) + (status.value?.dayBytesDown ?? 0)))
const deniedTotal = computed(() => {
  const d = status.value?.denied
  return d ? d['400'] + d['407'] + d['502'] : 0
})

const rangeLabel = computed(() => ({ '1h': '近 1 小时', '24h': '近 24 小时', '7d': '近 7 天' }[range.value]))

async function refreshStatus() {
  try { status.value = await apiStatus() } catch (_) {}
}

async function loadTraffic() {
  try {
    const points = await apiTraffic(range.value)
    renderChart(points)
  } catch (_) {}
}

function renderChart(points: TrafficPoint[]) {
  const labels = points.map((p) => {
    const d = new Date(p.ts)
    const p2 = (x: number) => String(x).padStart(2, '0')
    const time = `${p2(d.getHours())}:${p2(d.getMinutes())}`
    return range.value === '7d' ? `${d.getMonth() + 1}-${d.getDate()} ${time}` : time
  })
  setOption({
    tooltip: {
      trigger: 'axis',
      valueFormatter: (v: unknown) => fmtBytes(Number(v)),
    },
    legend: { data: ['上行', '下行'], top: 0 },
    grid: { left: 60, right: 20, top: 40, bottom: 30 },
    xAxis: { type: 'category', data: labels, boundaryGap: false },
    yAxis: { type: 'value', axisLabel: { formatter: (v: number) => fmtBytes(v) } },
    series: [
      {
        name: '上行', type: 'line', data: points.map((p) => p.up), smooth: true,
        showSymbol: false, lineStyle: { width: 2 }, areaStyle: { opacity: 0.08 },
      },
      {
        name: '下行', type: 'line', data: points.map((p) => p.down), smooth: true,
        showSymbol: false, lineStyle: { width: 2 }, areaStyle: { opacity: 0.08 },
      },
    ],
  })
}

onMounted(() => {
  refreshStatus()
  loadTraffic()
  timer = window.setInterval(refreshStatus, 5000)
})

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer)
})
</script>

<template>
  <n-space vertical :size="16">
    <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" item-responsive>
      <n-gi span="2 s:1">
        <n-card size="small">
          <n-statistic label="活跃连接" :value="activeConns" />
        </n-card>
      </n-gi>
      <n-gi span="2 s:1">
        <n-card size="small">
          <n-statistic label="本次进程转发流量" :value="totalBytes" />
        </n-card>
      </n-gi>
      <n-gi span="2 s:1">
        <n-card size="small">
          <n-statistic label="本次进程今日流量" :value="todayBytes" />
          <template #footer>
            <n-text depth="3" style="font-size: 12px">今日连接 {{ status?.todayConns ?? 0 }} · 拒绝 {{ deniedTotal }}</n-text>
          </template>
        </n-card>
      </n-gi>
      <n-gi span="2 s:1">
        <n-card size="small">
          <n-statistic label="运行时长" :value="uptime" />
          <template #footer>
            <n-text depth="3" style="font-size: 12px">
              v{{ status?.server.version ?? '-' }} · node {{ status?.server.node ?? '-' }} · PID {{ status?.server.pid ?? '-' }}
            </n-text>
          </template>
        </n-card>
      </n-gi>
    </n-grid>

    <n-card size="small">
      <template #header>
        <div style="display: flex; justify-content: space-between; align-items: center">
          <span>流量历史（{{ rangeLabel }}）</span>
          <n-radio-group v-model:value="range" size="small" @update:value="loadTraffic">
            <n-radio-button value="1h">1小时</n-radio-button>
            <n-radio-button value="24h">24小时</n-radio-button>
            <n-radio-button value="7d">7天</n-radio-button>
          </n-radio-group>
        </div>
      </template>
      <div ref="chartEl" style="height: 320px; width: 100%" />
    </n-card>
  </n-space>
</template>
