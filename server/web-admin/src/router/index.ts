import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('../views/Login.vue') },
    { path: '/', name: 'dashboard', component: () => import('../views/Dashboard.vue') },
    { path: '/tunnels', name: 'tunnels', component: () => import('../views/Tunnels.vue') },
    { path: '/logs', name: 'logs', component: () => import('../views/Logs.vue') },
    { path: '/config', name: 'config', component: () => import('../views/Config.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (to.path !== '/login' && !localStorage.getItem('admin_token')) return '/login'
  if (to.path === '/login' && localStorage.getItem('admin_token')) return '/'
})

export default router
