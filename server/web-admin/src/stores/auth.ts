import { defineStore } from 'pinia'
import { ref } from 'vue'
import { apiLogin, client } from '../api/client'

const TOKEN_KEY = 'admin_token'

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(localStorage.getItem(TOKEN_KEY))

  async function login(password: string) {
    const t = await apiLogin(password)
    token.value = t
    localStorage.setItem(TOKEN_KEY, t)
  }

  function logout() {
    const previous = token.value
    token.value = null
    localStorage.removeItem(TOKEN_KEY)
    // Revoke server-side session too; local logout must still succeed offline.
    if (previous) {
      void client.post('/logout', {}, {
        headers: { Authorization: `Bearer ${previous}` },
      }).catch(() => {})
    }
  }

  return { token, login, logout }
})
