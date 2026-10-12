'use strict';
const { Resolver } = require('dns').promises;
const net = require('net');

// Separate resolvers let one address family time out/cancel without poisoning
// the other. The first usable family is enough to begin connecting.
function resolveAddresses(host, timeoutMs, injected) {
  if (net.isIP(host)) {
    const ips = [host];
    return { first: Promise.resolve({ ips, index: 0 }), tasks: [Promise.resolve(ips)],
      balanced: async () => ips,
      cancel() {} };
  }
  const cancels = [];
  const tasks = ['resolve4', 'resolve6'].map((method) => new Promise(resolve => {
    const resolver = injected || new Resolver({ timeout: timeoutMs, tries: 1 });
    let finished = false;
    let timer;
    const finish = ips => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(ips);
    };
    const cancel = () => {
      if (finished) return;
      // Settle first: resolver.cancel() rejects outstanding query promises.
      finish([]);
      if (!injected && typeof resolver.cancel === 'function') resolver.cancel();
    };
    cancels.push(cancel);
    timer = setTimeout(cancel, timeoutMs);
    timer.unref();
    Promise.resolve().then(() => resolver[method](host)).then(
      ips => finish(Array.isArray(ips) ? ips.filter(ip => net.isIP(ip)) : []),
      () => finish([]),
    );
  }));
  const first = Promise.any(tasks.map((task, index) => task.then(ips => {
    if (!ips.length) throw new Error('no address in family');
    return { ips, index };
  })));
  return { first, tasks,
    async balanced() {
      const { ips, index } = await first;
      const other = await grace(tasks[1 - index]);
      const out = [];
      for (let i = 0; i < Math.max(ips.length, other.length); i++) {
        if (ips[i]) out.push(ips[i]);
        if (other[i]) out.push(other[i]);
      }
      return out;
    },
    cancel() { for (const cancel of cancels) cancel(); } };
}

async function grace(promise, ms = 100) {
  let timer;
  try {
    return await Promise.race([promise, new Promise(resolve => {
      timer = setTimeout(() => resolve([]), ms);
      timer.unref();
    })]);
  } finally { clearTimeout(timer); }
}

module.exports = { resolveAddresses, grace };
