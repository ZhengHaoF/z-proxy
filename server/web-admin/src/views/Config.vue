<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { NCard, NDescriptions, NDescriptionsItem, NTag, NSpace, NText, NSpin } from 'naive-ui'
import { apiConfig, type AdminConfig } from '../api/client'

const cfg = ref<AdminConfig | null>(null)
const loading = ref(true)

onMounted(async () => {
  try { cfg.value = await apiConfig() } finally { loading.value = false }
})
</script>

<template>
  <n-spin :show="loading">
    <n-space vertical :size="16">
      <n-card title="转发面" size="small">
        <n-descriptions v-if="cfg" bordered :column="2" size="small">
          <n-descriptions-item label="监听端口">{{ cfg.forward.port }}</n-descriptions-item>
          <n-descriptions-item label="监听地址">{{ cfg.forward.host }}</n-descriptions-item>
          <n-descriptions-item label="空闲超时（秒）">{{ cfg.forward.idleTimeoutSec }}（0 = 关闭）</n-descriptions-item>
          <n-descriptions-item label="转发密钥">
            <n-tag size="small" :type="cfg.forward.tokenSet ? 'success' : 'warning'">
              {{ cfg.forward.tokenSet ? '已设置' : '使用默认值（z-proxy-dev）' }}
            </n-tag>
          </n-descriptions-item>
        </n-descriptions>
      </n-card>

      <n-card title="管理面" size="small">
        <n-descriptions v-if="cfg" bordered :column="2" size="small">
          <n-descriptions-item label="管理端口">{{ cfg.admin.port }}</n-descriptions-item>
          <n-descriptions-item label="管理地址">{{ cfg.admin.host }}</n-descriptions-item>
          <n-descriptions-item label="后台密码">
            <n-tag size="small" :type="cfg.admin.passwordSet ? 'success' : 'error'">
              {{ cfg.admin.passwordSet ? '已配置（server/.env）' : '未配置！使用默认密码 admin' }}
            </n-tag>
          </n-descriptions-item>
          <n-descriptions-item label="登录 token 有效期">{{ cfg.admin.tokenTtlHours }} 小时</n-descriptions-item>
        </n-descriptions>
      </n-card>

      <n-card title="存储与运行环境" size="small">
        <n-descriptions v-if="cfg" bordered :column="2" size="small">
          <n-descriptions-item label="数据库">{{ cfg.db.path }}</n-descriptions-item>
          <n-descriptions-item label="日志模式">{{ cfg.db.journal }}</n-descriptions-item>
          <n-descriptions-item label="Node 版本">{{ cfg.node }}</n-descriptions-item>
          <n-descriptions-item label="说明">
            <n-text depth="3" style="font-size: 12px">配置项为只读，修改需编辑环境变量 / .env 后重启</n-text>
          </n-descriptions-item>
        </n-descriptions>
      </n-card>
    </n-space>
  </n-spin>
</template>
