// extension/src/worker.ts
var native = null;
var waiting = /* @__PURE__ */ new Map();
var sites = /* @__PURE__ */ new Map();
var pendingApprovals = /* @__PURE__ */ new Map();
var utf8 = new TextEncoder();
var publicMethod = /^(?:(?:eth_|net_|web3_|wallet_)[A-Za-z0-9_]+|personal_sign)$/;
var unavailable = { code: 4900, message: "Vault unavailable. Run vault browser-wallet install, then retry." };
function nativePort() {
  if (native) return native;
  const p = chrome.runtime.connectNative("com.grexie.vault");
  native = p;
  p.onMessage.addListener((m) => {
    if (!m || typeof m.id !== "string") return;
    const q = waiting.get(m.id);
    if (!q) return;
    clearTimeout(q.timer);
    waiting.delete(m.id);
    if (m.error && typeof m.error.code === "number" && typeof m.error.message === "string") q.reject(m.error);
    else q.resolve(m.result ?? null);
  });
  p.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    native = null;
    for (const q of waiting.values()) {
      clearTimeout(q.timer);
      q.reject(unavailable);
    }
    waiting.clear();
    for (const port of sites.keys()) stateMessage(port, null);
  });
  return p;
}
function call(origin, method, params = [], owner) {
  const id = crypto.randomUUID();
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      waiting.delete(id);
      native?.postMessage({ id: crypto.randomUUID(), cancel: id });
      reject({ code: 4001, message: "Vault request expired" });
    }, 11 * 60 * 1e3);
    waiting.set(id, { resolve, reject, timer, owner });
    try {
      nativePort().postMessage({ id, origin, method, params });
    } catch {
      clearTimeout(timer);
      waiting.delete(id);
      reject(unavailable);
    }
  });
  return { id, done };
}
function cancel(id) {
  const q = waiting.get(id);
  if (!q) return;
  waiting.delete(id);
  clearTimeout(q.timer);
  native?.postMessage({ id: crypto.randomUUID(), cancel: id });
  q.reject({ code: 4001, message: "Website cancelled this request" });
}
function stateMessage(port, state) {
  try {
    port.postMessage({ event: "state", state: { available: !!state, accounts: state?.connected && state.permission ? [state.permission.address] : [], chainId: state?.chain.chainId || "0x1" } });
  } catch {
  }
}
async function refresh(port) {
  const site = sites.get(port);
  if (!site) return;
  try {
    stateMessage(port, await call(site.origin, "_state", [], port).done);
  } catch {
    stateMessage(port, null);
  }
}
function actualOrigin(sender) {
  if (sender.id !== chrome.runtime.id || sender.frameId !== 0 || !sender.tab?.url || !sender.url || !sender.origin) return null;
  try {
    const origin = new URL(sender.tab.url).origin;
    if (origin !== sender.origin || new URL(sender.url).origin !== origin || origin === "null") return null;
    return origin;
  } catch {
    return null;
  }
}
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "vault-provider-v1") return;
  const origin = port.sender ? actualOrigin(port.sender) : null;
  if (!origin) {
    port.disconnect();
    return;
  }
  const site = { origin, tabId: port.sender.tab.id, requests: /* @__PURE__ */ new Map() };
  sites.set(port, site);
  void refresh(port);
  port.onMessage.addListener((m) => {
    if (!m || typeof m !== "object") return;
    if (typeof m.cancel === "string") {
      const id = site.requests.get(m.cancel);
      if (id) cancel(id);
      return;
    }
    if (typeof m.id !== "string" || m.id.length === 0 || m.id.length > 80 || site.requests.has(m.id) || site.requests.size >= 32 || typeof m.method !== "string" || !Array.isArray(m.params)) return;
    if (m.method.length > 80 || !publicMethod.test(m.method)) {
      port.postMessage({ id: m.id, error: { code: 4200, message: "Unsupported wallet method" } });
      return;
    }
    try {
      if (utf8.encode(JSON.stringify(m.params)).byteLength > 180 * 1024) {
        port.postMessage({ id: m.id, error: { code: -32602, message: "Request exceeds size limit" } });
        return;
      }
    } catch {
      port.postMessage({ id: m.id, error: { code: -32602, message: "Invalid wallet parameters" } });
      return;
    }
    const request = call(origin, m.method, m.params, port);
    site.requests.set(m.id, request.id);
    if (/sign|sendTransaction|requestAccounts|requestPermissions|switchEthereumChain|addEthereumChain/i.test(m.method)) pendingApprovals.set(request.id, { origin, method: m.method });
    request.done.then((result) => {
      try {
        port.postMessage({ id: m.id, result });
      } catch {
      }
    }, (error) => {
      try {
        port.postMessage({ id: m.id, error });
      } catch {
      }
    }).finally(() => {
      site.requests.delete(m.id);
      pendingApprovals.delete(request.id);
      void refresh(port);
    });
  });
  port.onDisconnect.addListener(() => {
    for (const id of site.requests.values()) cancel(id);
    for (const [id, q] of waiting) if (q.owner === port) cancel(id);
    sites.delete(port);
  });
});
setInterval(() => {
  for (const port of sites.keys()) void refresh(port);
}, 8e3);
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL("popup.html") || sender.tab) return false;
  if (!message || !["status", "retry", "change"].includes(message.action)) return false;
  void (async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id === void 0) throw unavailable;
      const known = [...new Set([...sites.values()].filter((site) => site.tabId === tab.id).map((site) => site.origin))];
      const origin = tab.url ? new URL(tab.url).origin : known.length === 1 ? known[0] : null;
      if (!origin || origin === "null" || known.length !== 1 || known[0] !== origin) throw unavailable;
      if (message.action === "change") {
        const request = call(origin, "_changeIdentity");
        pendingApprovals.set(request.id, { origin, method: "Change identity" });
        try {
          await request.done;
        } finally {
          pendingApprovals.delete(request.id);
        }
      }
      const state = await call(origin, "_state").done;
      respond({ state, origin, pending: [...pendingApprovals.values()].find((p) => p.origin === origin) || null });
      for (const port of sites.keys()) void refresh(port);
    } catch {
      respond({ error: unavailable });
    }
  })();
  return true;
});
