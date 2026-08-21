/**
 * pm2 部署配置 —— zhihu-proxy 服务端
 *
 * 用法（在服务器上的项目根目录执行）：
 *   pm2 delete zhihu-proxy      # 如有旧进程先删
 *   pm2 start ecosystem.config.js
 *   pm2 save                    # 固化，重启后自启仍用此配置
 *
 * 说明：
 *   - name 即 pm2 进程名（替换原先自动命名的 server）
 *   - env 里的 PROXY_TOKEN / PORT 会注入到 server.js 的环境变量
 *   - 若把本项目推到 git，建议把真实 token 移出此文件（见下方注释的 .env 方案）
 */
module.exports = {
  apps: [
    {
      name: 'zhihu-proxy',
      script: 'server/server.js',
      cwd: __dirname,            // 以项目根目录为基准解析 server/server.js
      instances: 1,              // 转发代理是有状态监听端口，单实例即可
      autorestart: true,
      watch: false,              // 不监听文件变更自动重启
      max_memory_restart: '256M',
      env: {
        PROXY_TOKEN: '54ZhengHF',
        PORT: 8443,
        HOST: '0.0.0.0',
      },
      // 更安全做法：把 token 放到同目录 .env（不进 git），这里改为读取环境变量：
      //   env: { PROXY_TOKEN: process.env.ZHIHU_PROXY_TOKEN || '', PORT: 8443, HOST: '0.0.0.0' }
      // 然后服务器上执行： ZHIHU_PROXY_TOKEN='54ZhengHF' pm2 start ecosystem.config.js
    },
  ],
};
