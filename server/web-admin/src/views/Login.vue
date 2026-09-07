<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { NCard, NInput, NButton, NForm, NFormItem, NAlert, useMessage } from 'naive-ui'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const auth = useAuthStore()
const message = useMessage()

const password = ref('')
const loading = ref(false)
const error = ref('')

async function submit() {
  if (!password.value) { error.value = '请输入后台密码'; return }
  loading.value = true
  error.value = ''
  try {
    await auth.login(password.value)
    message.success('登录成功')
    router.push('/')
  } catch (e: any) {
    error.value = e?.response?.data?.error || '登录失败，请检查密码'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div style="height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--n-color, #f5f6f8)">
    <n-card style="width: 360px" title="z-proxy 管理台">
      <n-form @submit.prevent="submit">
        <n-form-item label="后台密码" show-feedback>
          <n-input
            v-model:value="password"
            type="password"
            show-password-on="click"
            placeholder="请输入 ADMIN_PASSWORD"
            @keyup.enter="submit"
          />
        </n-form-item>
        <n-alert v-if="error" type="error" :show-icon="false" style="margin-bottom: 12px">
          {{ error }}
        </n-alert>
        <n-button type="primary" block :loading="loading" attr-type="submit">登 录</n-button>
      </n-form>
    </n-card>
  </div>
</template>
