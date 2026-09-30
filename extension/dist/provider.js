"use strict";
(() => {
  // extension/src/provider.ts
  var error = (code, message) => Object.assign(new Error(message), { code });
  var utf8 = new TextEncoder();
  var publicMethod = /^(?:(?:eth_|net_|web3_|wallet_)[A-Za-z0-9_]+|personal_sign)$/;
  var VaultProvider = class {
    isGrexieVault = true;
    #listeners = /* @__PURE__ */ new Map();
    #requests = /* @__PURE__ */ new Map();
    #available = false;
    #accounts = [];
    #chainId = "0x1";
    constructor() {
      window.addEventListener("message", (event) => {
        if (event.source !== window || event.origin !== location.origin || !event.data || event.data.target !== "grexie-vault:page" || event.data.version !== 1) return;
        const message = event.data;
        if (message.event === "state") {
          const state = message.state;
          if (!state || typeof state.available !== "boolean") return;
          if (state.available && !this.#available) this.#emit("connect", { chainId: state.chainId || this.#chainId });
          if (!state.available && this.#available) this.#emit("disconnect", error(4900, "Vault unavailable"));
          this.#available = state.available;
          const accounts = state.available && Array.isArray(state.accounts) ? state.accounts : [];
          if (accounts.every((a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a)) && JSON.stringify(accounts) !== JSON.stringify(this.#accounts)) {
            this.#accounts = accounts;
            this.#emit("accountsChanged", [...accounts]);
          }
          if (typeof state.chainId === "string" && /^0x[0-9a-f]+$/.test(state.chainId) && state.chainId !== this.#chainId) {
            this.#chainId = state.chainId;
            this.#emit("chainChanged", this.#chainId);
          }
          return;
        }
        if (typeof message.id !== "string") return;
        const request = this.#requests.get(message.id);
        if (!request) return;
        clearTimeout(request.timer);
        this.#requests.delete(message.id);
        if (message.error && Number.isInteger(message.error.code) && typeof message.error.message === "string") request.reject(error(message.error.code, message.error.message));
        else request.resolve(message.result ?? null);
      });
      window.addEventListener("pagehide", () => {
        for (const [id, p] of this.#requests) {
          clearTimeout(p.timer);
          p.reject(error(4900, "Page disconnected"));
          window.postMessage({ target: "grexie-vault:content", version: 1, cancel: id }, location.origin);
        }
        this.#requests.clear();
      });
    }
    request(args) {
      if (!args || typeof args.method !== "string" || args.params !== void 0 && !Array.isArray(args.params)) return Promise.reject(error(-32602, "Invalid wallet request"));
      if (args.method.length > 80 || !publicMethod.test(args.method)) return Promise.reject(error(4200, "Unsupported wallet method"));
      try {
        if (utf8.encode(JSON.stringify(args.params || [])).byteLength > 180 * 1024) return Promise.reject(error(-32602, "Wallet request exceeds size limit"));
      } catch {
        return Promise.reject(error(-32602, "Invalid wallet parameters"));
      }
      if (this.#requests.size >= 32) return Promise.reject(error(-32002, "Too many pending requests"));
      const id = crypto.randomUUID();
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          this.#requests.delete(id);
          window.postMessage({ target: "grexie-vault:content", version: 1, cancel: id }, location.origin);
          reject(error(4001, "Vault request expired"));
        }, 11 * 60 * 1e3);
        this.#requests.set(id, { resolve, reject, timer });
        try {
          window.postMessage({ target: "grexie-vault:content", version: 1, id, method: args.method, params: args.params || [] }, location.origin);
        } catch {
          clearTimeout(timer);
          this.#requests.delete(id);
          reject(error(-32602, "Invalid wallet parameters"));
        }
      });
    }
    on(event, listener) {
      if (typeof listener !== "function") throw error(-32602, "Listener must be a function");
      let set = this.#listeners.get(event);
      if (!set) {
        set = /* @__PURE__ */ new Set();
        this.#listeners.set(event, set);
      }
      set.add(listener);
      return this;
    }
    removeListener(event, listener) {
      this.#listeners.get(event)?.delete(listener);
      return this;
    }
    removeAllListeners(event) {
      if (event) this.#listeners.delete(event);
      else this.#listeners.clear();
      return this;
    }
    isConnected() {
      return this.#available;
    }
    get selectedAddress() {
      return this.#accounts[0] || null;
    }
    get chainId() {
      return this.#chainId;
    }
    get networkVersion() {
      return BigInt(this.#chainId).toString();
    }
    enable() {
      return this.request({ method: "eth_requestAccounts" });
    }
    // Compatibility for older web3.js clients; all paths share request validation.
    sendAsync(payload, callback) {
      this.request(payload).then((result) => callback(null, { jsonrpc: "2.0", id: payload.id, result }), (e) => callback(e));
    }
    send(method, params) {
      if (typeof method === "string") return this.request({ method, params: Array.isArray(params) ? params : [] });
      if (typeof params === "function") return this.sendAsync(method, params);
      return this.request(method);
    }
    #emit(event, value) {
      for (const listener of this.#listeners.get(event) || []) {
        try {
          listener(value);
        } catch {
        }
      }
    }
  };
  var provider = new VaultProvider();
  var detail = Object.freeze({ info: Object.freeze({ uuid: crypto.randomUUID(), name: "Grexie Vault", icon: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAFBklEQVR4nOxXXYhVVRT+1jrn3PlpphJHRQJtwBQrah6kpyIqonpsEKHSJiOKIKMfSsgg8KVnwaAHsz8JIfWhl8LoKTFM6Aem0IbAQtB0xhnn955z9l4r1t7nzB3H8UIP4Yt7OJy5e++7vm9969trzzCu87hB4AaBdPHEwI4nVixb3feKeL2jq6sTEEHWaIDASNIECTGSJAUzI0sSJPZQgjRLkKaZkoJsjpnCXrJ1JvQ2ekYwMbv3nS2vXmxHIOm+ufvghXPnH+7oEvz5yyT6Vq3C2LmL6O3pRbPZRF7kAZQTDiSIGUmWxrmUW2tGNmGAABBh5coVWL+2/wEAjwLwNSAtRF/3zH13Iun6tZmMp/fuvE1+2nUW99z/EA0fPY6+nuWYmBrXy82pKkMDJyVmMkAjEoBba0EFexMRvAr1b+z3jGTg2137h5dUQIk7VT3PnMlx7LXTwHSCk0eOwovHzKUJaELgLIF6bwHBQmQAKhxAlBmeqAJncPg9kqGEMTkxSd3dHZ1tPcAZK48XuAldKHyBspwDqyosFkJgNTCKwYkAtQ91ppaHKetVcWlqUl1ZknpB1t3AyjWr0JF0aFsC4jx6unqRcgNuxoNF1PABWggc3pxEMvVaRA98NPildIBAVQmcexLxQNb2FGQg0iC5y2eR5zk8BA7efIRUE0AoWIjsh1oma5mKICqYnp62zBWilSaAKbF4XEGA2KkoQ7zAlS4SyQQDj2/C1MwUTv94CukcWe2hEsHm9axJKFAUOcQ5DYui8/NGDOWiki/8oLmSigapjISIoPAl7h64C/s+2EtDbwyho78XeeYgLHDi4M2Q3sM5B+9cAPdlCRWFeg1vaFTBe0FZlm1KYPVRVRENwYxEyoxDnx222ur2LU/jsQcfwZ59H+LENz+AJgRaSFAjZKsK710EraUP4BTdIWL+0WsqQI40ZO5bCqgTzJy9jI/3fIKtO17CmX/+xp733sdbu98E35JB1Qj48MyD64Kn1t84WTwRuqYCZlclkG2sNkM51tFUcc6j8A52HNMkjQmSRoMZGEdfRDxDrD1AV5lv6RKgUqpSwYIoE7pX92BwaBDPP7UVF8fG8Prud3Hs6++BaQ+Xih2PBXJHUPYcygOZTy4k5dhfuw8EexAobg7wKNVj89BmvDj0HPZ/cQAHP/8Sl/8aQ+oZt65ZjsFtTyLraEQFrKZEyPMChz86hPGRC1Ed0aiBavsShD0iGuSvnJWAMfzzb9h+7GX8fmIYaZOQejt+EoA3bNyArs7OeQLWkJrNHI3ujgAeGhRVNrA9ZbsSFGXo91rVPHTggnDyq+MhdIZoUsvEWu/oyHm8/cJOQmqdMPTkqGEpSrMSvCK2N4KH75ZocwztdjPQ6OzQQ6GFt9NhYVVCX62ysYvfCTBnNyJVuVerErueuvokRGLaOhZLE7AmNO9ojcmgUgJodTRUS6FKFpZq76O1R+IpsBWuu+TVnXhxCZS0YbdB1b4rEjWhus7QqrNUgc0R1cwVo9aFYn3it9oRmB2dmOS+Hrdi3epGPjFnvZsWBFt8oO0SNskCT44vqhbiFV0RMGpFQ6goynLy/KXJxSSvGD2b1n5KKT/baibaKglVqtTOjtLXdCIYx7ngC4qP/WUkUKQJHxj97tS2tgTsRuDblw1CdP0Sa+1GLALP1zp8ZkO3DpnwH+XI6BEr9H+M+/+O6/5/wQ0C153AvwEAAP//5WDqIxlDAWkAAAAASUVORK5CYII=", rdns: "com.grexie.vault" }), provider });
  var announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
  var page = window;
  if (!page.ethereum) {
    try {
      Object.defineProperty(page, "ethereum", { value: provider, writable: false, configurable: true });
      window.dispatchEvent(new Event("ethereum#initialized"));
    } catch {
    }
  }
  Object.defineProperty(page, "grexieVault", { value: provider, writable: false, configurable: false });
})();
