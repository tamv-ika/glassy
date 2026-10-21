// Helpers shared by the spike pages.

window.loadConnectInfo = async function loadConnectInfo() {
  const res = await fetch('/connect.json', { cache: 'no-store' });
  if (!res.ok) throw new Error(`connect.json: HTTP ${res.status}`);
  return res.json();
};

window.withTimeout = function withTimeout(promise, ms, what) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what ?? 'operation'} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
};
