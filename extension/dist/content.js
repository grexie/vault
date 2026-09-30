"use strict";
(() => {
  // extension/src/content.ts
  var port = chrome.runtime.connect({ name: "vault-provider-v1" });
  var pending = /* @__PURE__ */ new Set();
  var utf8 = new TextEncoder();
  var publicMethod = /^(?:(?:eth_|net_|web3_|wallet_)[A-Za-z0-9_]+|personal_sign)$/;
  var post = (message) => window.postMessage({ target: "grexie-vault:page", version: 1, ...message }, location.origin);
  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin || !event.data || event.data.target !== "grexie-vault:content" || event.data.version !== 1) return;
    const m = event.data;
    if (typeof m.cancel === "string" && pending.has(m.cancel)) {
      port.postMessage({ cancel: m.cancel });
      pending.delete(m.cancel);
      return;
    }
    if (typeof m.id !== "string" || m.id.length === 0 || m.id.length > 80 || pending.has(m.id) || pending.size >= 32 || typeof m.method !== "string" || !Array.isArray(m.params)) return;
    if (m.method.length > 80 || !publicMethod.test(m.method)) {
      post({ id: m.id, error: { code: 4200, message: "Unsupported wallet method" } });
      return;
    }
    try {
      if (utf8.encode(JSON.stringify(m.params)).byteLength > 180 * 1024) {
        post({ id: m.id, error: { code: -32602, message: "Wallet request exceeds size limit" } });
        return;
      }
      pending.add(m.id);
      port.postMessage({ id: m.id, method: m.method, params: m.params });
    } catch {
      pending.delete(m.id);
      post({ id: m.id, error: { code: -32602, message: "Invalid wallet parameters" } });
    }
  });
  port.onMessage.addListener((m) => {
    if (m.event === "state") {
      post(m);
      return;
    }
    if (typeof m.id === "string" && pending.has(m.id)) {
      pending.delete(m.id);
      post(m);
    }
  });
  port.onDisconnect.addListener(() => {
    post({ event: "state", state: { available: false, accounts: [] } });
    for (const id of pending) post({ id, error: { code: 4900, message: "Vault extension disconnected" } });
    pending.clear();
  });
  window.addEventListener("pagehide", () => port.disconnect());
})();
