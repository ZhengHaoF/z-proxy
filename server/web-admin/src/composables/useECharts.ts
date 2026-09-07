// 轻量 echarts 封装：初始化、resize、销毁
import * as echarts from 'echarts'
import { onBeforeUnmount, onMounted, type Ref } from 'vue'

export function useECharts(elRef: Ref<HTMLElement | null>) {
  let chart: echarts.ECharts | null = null
  let ro: ResizeObserver | null = null

  onMounted(() => {
    if (!elRef.value) return
    chart = echarts.init(elRef.value)
    ro = new ResizeObserver(() => chart?.resize())
    ro.observe(elRef.value)
  })

  onBeforeUnmount(() => {
    ro?.disconnect()
    chart?.dispose()
    chart = null
  })

  function setOption(option: echarts.EChartsOption) {
    chart?.setOption(option, true)
  }

  return { setOption }
}
