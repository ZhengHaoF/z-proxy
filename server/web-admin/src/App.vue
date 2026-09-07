<script setup lang="ts">
import { computed, h } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  NConfigProvider, NMessageProvider, NDialogProvider, NLayout, NLayoutSider, NLayoutHeader,
  NLayoutContent, NMenu, NButton, NIcon, NText, zhCN, dateZhCN,
  type MenuOption,
} from 'naive-ui'
import {
  SpeedometerOutline, GitNetworkOutline, DocumentTextOutline, SettingsOutline, LogOutOutline,
} from '@vicons/ionicons5'
import { useAuthStore } from './stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const isLogin = computed(() => route.path === '/login')

const menuOptions: MenuOption[] = [
  { label: '状态总览', key: '/', icon: () => h(NIcon, null, { default: () => h(SpeedometerOutline) }) },
  { label: '实时隧道', key: '/tunnels', icon: () => h(NIcon, null, { default: () => h(GitNetworkOutline) }) },
  { label: '实时日志', key: '/logs', icon: () => h(NIcon, null, { default: () => h(DocumentTextOutline) }) },
  { label: '运行配置', key: '/config', icon: () => h(NIcon, null, { default: () => h(SettingsOutline) }) },
]

function onMenu(key: string) {
  router.push(key)
}

function onLogout() {
  auth.logout()
  router.push('/login')
}
</script>

<template>
  <n-config-provider :locale="zhCN" :date-locale="dateZhCN">
    <n-message-provider>
      <n-dialog-provider>
        <router-view v-if="isLogin" />

        <n-layout v-else has-sider style="height: 100vh">
          <n-layout-sider bordered :width="200" collapse-mode="width" :collapsed-width="0" show-trigger="arrow-circle">
            <div style="padding: 18px 16px 12px">
              <n-text strong style="font-size: 15px">z-proxy</n-text>
              <div style="font-size: 12px; opacity: 0.55; margin-top: 2px">Web 管理台</div>
            </div>
            <n-menu :value="route.path" :options="menuOptions" @update:value="onMenu" />
          </n-layout-sider>

          <n-layout>
            <n-layout-header bordered style="height: 52px; display: flex; align-items: center; justify-content: space-between; padding: 0 16px">
              <n-text style="font-size: 14px">{{ route.meta?.title || '管理台' }}</n-text>
              <n-button quaternary size="small" @click="onLogout">
                <template #icon><n-icon><LogOutOutline /></n-icon></template>
                退出
              </n-button>
            </n-layout-header>
            <n-layout-content content-style="padding: 16px">
              <router-view />
            </n-layout-content>
          </n-layout>
        </n-layout>
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>
