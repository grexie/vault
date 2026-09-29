import {
  b64,
  unb64,
  optionsFromJSON,
  publicCredential,
  sealVault,
  openVault,
  sealGrant,
} from "./crypto.js";

const root = document.querySelector("#app");
let state = null,
  tab = "requests",
  busy = false,
  info;
const esc = (v) =>
  String(v ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const icon = (name) =>
  ({ key: "⌘", lock: "▣", clock: "◷", terminal: "›_", phone: "▯", check: "✓" })[
    name
  ] || "";
async function api(path, body, method) {
  const res = await fetch(path, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  const v = await res.json();
  if (!res.ok) {
    if (res.status === 401) {
      state = null;
      renderLogin();
    }
    throw new Error(v.error || "Request failed");
  }
  return v;
}
function toast(text, error = false) {
  const m = document.querySelector("#message");
  m.textContent = text;
  m.className = error ? "visible error" : "visible";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (m.className = ""), error ? 12000 : 6500);
}
async function action(fn) {
  if (busy) return;
  busy = true;
  root.classList.add("busy");
  try {
    await fn();
  } catch (e) {
    const message =
      e.name === "NotAllowedError"
        ? "Passkey verification was cancelled or is unavailable."
        : e.name === "NotSupportedError"
          ? "This device or passkey provider does not support both PRF and largeBlob storage. No key was saved."
          : e.message;
    toast(message, true);
  } finally {
    busy = false;
    root.classList.remove("busy");
  }
}
async function credential(options, create = false, blob) {
  const publicKey = optionsFromJSON(options);
  if (blob) publicKey.extensions.largeBlob.write = blob;
  return navigator.credentials[create ? "create" : "get"]({ publicKey });
}
function verifyBrowser() {
  if (
    !window.isSecureContext ||
    !navigator.credentials ||
    !window.PublicKeyCredential
  )
    throw new Error(
      "Open this app over HTTPS in a browser with passkey support.",
    );
}
function renderSetup() {
  root.innerHTML = `<section class="onboarding"><h1>Connect your keychain</h1><p>Create a passkey, then add your SSH key.</p><form id="setup"><label for="setup-token">One-time setup token</label><input id="setup-token" name="token" autocomplete="off" type="password" required placeholder="From the server’s first startup"><button class="primary" type="submit">Create a passkey</button></form><p class="small">Your passkey provider must support PRF encryption and largeBlob storage. Setup checks both before saving anything.</p></section>`;
  document.querySelector("#setup").onsubmit = (e) => {
    e.preventDefault();
    action(async () => {
      verifyBrowser();
      const token = e.target.token.value;
      const start = await api("/api/setup/begin", { token });
      const c = await credential(start.options, true);
      const ext = c.getClientExtensionResults();
      if (!ext.prf?.enabled || !ext.largeBlob?.supported)
        throw new Error(
          "This passkey provider must support both PRF encryption and largeBlob storage. Try another provider.",
        );
      await api("/api/setup/finish", {
        ceremony: start.ceremony,
        credential: publicCredential(c),
      });
      tab = "keychain";
      await refresh();
      toast("Passkey connected. Paste your SSH key to finish setup.");
    });
  };
}
function renderLogin() {
  root.innerHTML = `<section class="onboarding"><h1>Sign in</h1><p>Use the passkey saved in your device’s keychain.</p><button id="login" class="primary">Sign in with a passkey</button><p class="small">Each SSH approval requires a separate verification.</p></section>`;
  document.querySelector("#login").onclick = () =>
    action(async () => {
      verifyBrowser();
      const start = await api("/api/auth/begin", {});
      const c = await credential(start.options);
      await api("/api/auth/finish", {
        ceremony: start.ceremony,
        credential: publicCredential(c),
      });
      await refresh();
    });
}
function minutes(n) {
  return n < 60 ? n + " sec" : Math.round(n / 60) + " min";
}
function countdown(q) {
  const end = new Date(q.status === "pending" ? q.pendingUntil : q.expiresAt);
  const sec = Math.max(0, Math.ceil((end - Date.now()) / 1000));
  return Math.floor(sec / 60) + ":" + String(sec % 60).padStart(2, "0");
}
function time(t) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
    day: "numeric",
  }).format(new Date(t));
}
function chrome(content) {
  const requests = Object.values(state.requests || {}),
    pending = requests.filter((q) => q.status === "pending").length;
  root.innerHTML = `<div class="workspace"><nav class="tabs" aria-label="Main navigation"><button data-tab="requests" class="${tab === "requests" ? "selected" : ""}">Requests ${pending ? `<span class="count">${pending}</span>` : ""}</button><button data-tab="keychain" class="${tab === "keychain" ? "selected" : ""}">Keychain</button><button data-tab="clients" class="${tab === "clients" ? "selected" : ""}">CLI clients</button><button id="signout" class="signout">Sign out</button></nav>${content}</div>`;
  root.querySelectorAll("[data-tab]").forEach(
    (b) =>
      (b.onclick = () => {
        if (busy) return;
        tab = b.dataset.tab;
        render();
      }),
  );
  document.querySelector("#signout").onclick = () =>
    action(async () => {
      await api("/api/logout", {});
      state = null;
      renderLogin();
    });
}
function render() {
  if (!state) return;
  const pages = {
    requests: renderRequests,
    keychain: renderKeychain,
    clients: renderClients,
  };
  pages[tab]();
}
function renderRequests() {
  const all = Object.values(state.requests || {}).sort(
    (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
  );
  const pending = all.filter((q) => q.status === "pending"),
    active = all.filter((q) => q.status === "active"),
    history = all.filter((q) => !["pending", "active"].includes(q.status));
  chrome(
    `<div class="page-heading"><div><h1>Requests</h1><p>${pending.length} awaiting approval · ${active.length} active</p></div><button id="notifications" class="secondary">Enable notifications</button></div>${!state.key.fingerprint ? '<div class="notice">Add your SSH key in <button id="open-keychain" class="text-button">Keychain</button> to get started.</div>' : ""}<section><div class="section-heading"><h2>Awaiting approval</h2></div>${pending.length ? pending.map(requestCard).join("") : '<div class="empty"><h3>No requests</h3><p>New SSH access requests will appear here.</p></div>'}</section><section class="section"><div class="section-heading"><h2>Active sessions</h2></div>${active.length ? active.map(requestCard).join("") : '<p class="empty-inline">No active sessions.</p>'}</section>${
      history.length
        ? `<section class="section"><div class="section-heading"><h2>Recent activity</h2></div><div class="history">${history
            .slice(0, 10)
            .map(
              (q) =>
                `<div class="history-row"><div><strong>${esc(q.session)}</strong><small>${esc(q.clientName)} · ${esc(time(q.createdAt))}</small></div><span class="badge ${esc(q.status)}">${esc(q.status)}</span></div>`,
            )
            .join("")}</div></section>`
        : ""
    }<p class="session-note">${state.pushSubscriptions ? `${state.pushSubscriptions} notification device${state.pushSubscriptions === 1 ? "" : "s"} connected.` : "For notifications, add this app to your Home Screen and enable them on each device."} Revoking access stops new authentication; existing SSH connections stay connected.</p>`,
  );
  document.querySelector("#notifications").onclick = () =>
    action(enableNotifications);
  document.querySelector("#open-keychain")?.addEventListener("click", () => {
    tab = "keychain";
    render();
  });
  root
    .querySelectorAll("[data-approve]")
    .forEach(
      (b) => (b.onclick = () => action(() => approve(b.dataset.approve))),
    );
  root.querySelectorAll("[data-revoke]").forEach(
    (b) =>
      (b.onclick = () =>
        action(async () => {
          await api("/api/requests/" + b.dataset.revoke + "/revoke", {});
          await refresh();
          toast("Access ended. The signer is locked.");
        })),
  );
  const focus = new URL(location.href).searchParams.get("request");
  if (focus)
    document
      .getElementById("request-" + focus)
      ?.scrollIntoView({ block: "nearest" });
}
function requestCard(q) {
  const pending = q.status === "pending";
  return `<article class="request-card" id="request-${esc(q.id)}"><div class="request-top"><div><h3>${esc(q.session)}</h3><p>${esc(q.clientName)}</p></div><span class="badge ${pending ? "pending" : "active"}">${pending ? "Pending" : "Active"}</span></div><p class="reason">${esc(q.reason)}</p><div class="request-details"><span>${esc(q.keyName)}</span><span>${minutes(q.durationSeconds)}</span><span class="remaining">${pending ? "Request expires" : "Access ends"} in <b data-countdown="${esc(q.id)}">${countdown(q)}</b></span></div><details><summary>Details</summary><dl><dt>Fingerprint</dt><dd>${esc(q.fingerprint)}</dd><dt>Requested socket</dt><dd>${esc(q.socket)}</dd><dt>Request ID</dt><dd>${esc(q.id)}</dd></dl><p class="small">The client supplied this session name, purpose, and socket path.</p></details><div class="request-actions">${pending ? `<button class="secondary" data-revoke="${esc(q.id)}">Deny</button><button class="primary" data-approve="${esc(q.id)}">Approve for ${minutes(q.durationSeconds)}</button>` : `<button class="danger" data-revoke="${esc(q.id)}">Revoke access</button>`}</div></article>`;
}
async function approve(id) {
  const start = await api("/api/requests/" + id + "/approve/begin", {});
  const c = await credential(start.options);
  const ext = c.getClientExtensionResults();
  let payload;
  try {
    payload = await openVault(
      ext.largeBlob?.blob,
      ext.prf?.results?.first,
      c.id,
    );
    if (payload.fingerprint !== start.request.fingerprint)
      throw new Error(
        "This device’s key does not match the requested key. Re-save it in Keychain.",
      );
    const envelope = await sealGrant(
      payload,
      start.publicKey,
      id,
      start.request.fingerprint,
    );
    await api("/api/requests/" + id + "/approve/finish", {
      ceremony: start.ceremony,
      credential: publicCredential(c),
      envelope,
    });
    await refresh();
    toast("Approved. The session will lock automatically.");
  } finally {
    if (payload) {
      payload.key = "";
      payload.passphrase = "";
    }
    if (ext.prf?.results?.first) new Uint8Array(ext.prf.results.first).fill(0);
  }
}
async function enableNotifications() {
  if (
    !("serviceWorker" in navigator) ||
    !("PushManager" in window) ||
    !("Notification" in window)
  )
    throw new Error(
      "Install this app on your Home Screen and open it there to enable notifications.",
    );
  // Permission is requested directly from this user gesture, before network calls.
  const permission = await Notification.requestPermission();
  if (permission !== "granted")
    throw new Error(
      "Notifications were not enabled. You can still review requests in the app.",
    );
  const registration = await navigator.serviceWorker.ready;
  let sub = await registration.pushManager.getSubscription();
  if (!sub)
    sub = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: unb64(state.vapidPublicKey),
    });
  await api("/api/push", sub.toJSON());
  await refresh();
  toast("Notifications enabled on this device.");
}
function parseKey(key, passphrase) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/key-worker.js");
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error("Key validation timed out. Check the key format."));
    }, 20000);
    worker.onmessage = (e) => {
      if (e.data.ready) {
        worker.postMessage({ key, passphrase });
        return;
      }
      clearTimeout(timer);
      worker.terminate();
      if (e.data.error) reject(new Error(e.data.error));
      else resolve(e.data);
    };
    worker.onerror = () => {
      clearTimeout(timer);
      worker.terminate();
      reject(
        new Error(
          "The local key validator could not start. Reload and try again.",
        ),
      );
    };
  });
}
function renderKeychain() {
  chrome(
    `<div class="page-heading"><div><h1>Your SSH key</h1><p>Stored with your passkey, encrypted on this device.</p></div><span class="badge ${state.key.fingerprint ? "active" : "pending"}">${state.key.fingerprint ? "Key connected" : "Setup needed"}</span></div><div class="key-layout"><form id="key-form" class="form-card"><h2>${state.key.fingerprint ? "Replace your saved key" : "Paste an existing key"}</h2><p>Paste the complete private key, including its BEGIN and END lines. Encrypted OpenSSH and PEM / PKCS#8 keys are supported.</p><label for="key-name">Key name</label><input name="keyName" id="key-name" required maxlength="80" value="${esc(state.key.name)}" placeholder="Personal SSH key"><label for="private-key">SSH private key</label><textarea name="privateKey" id="private-key" required spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" rows="9" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;Paste your private key here&#10;-----END OPENSSH PRIVATE KEY-----"></textarea><label for="key-passphrase">Existing key passphrase <span class="optional">if encrypted</span></label><input name="passphrase" id="key-passphrase" type="password" autocomplete="off" placeholder="The password that currently protects this key"><p class="small">The key is unlocked locally with its current passphrase, then re-encrypted with your passkey. The old passphrase is not saved. Two passkey prompts encrypt and save the key. ${state.key.fingerprint ? "Replacing the key revokes all open requests." : ""}</p><button class="primary" type="submit">${icon("key")} Save to device keychain</button></form><aside class="side-panel"><h3>Storage</h3><p>The server keeps your key’s name and fingerprint. It does not store the private key, passphrase, or encrypted keychain blob.</p>${state.key.fingerprint ? `<div class="fingerprint"><span>Saved fingerprint</span><code>${esc(state.key.fingerprint)}</code></div>` : ""}<hr><h3>Recovery</h3><p>Keychain storage limits and sync vary by provider. Confirm that the key is available on another device before depending on sync for recovery.</p><p class="small">An approval unlocks the key in a separate signer process on your server for that request’s lifetime.</p></aside></div>`,
  );
  document.querySelector("#key-form").onsubmit = (e) => {
    e.preventDefault();
    action(async () => {
      const form = e.target;
      let key = form.privateKey.value,
        passphrase = form.passphrase.value;
      try {
        verifyBrowser();
        toast("Validating the pasted key on this device…");
        const parsed = await parseKey(key, passphrase);
        const start = await api("/api/key/read/begin", {});
        const c = await credential(start.options);
        const prf = c.getClientExtensionResults().prf?.results?.first;
        const blob = await sealVault(
          {
            key: parsed.compact,
            passphrase: "",
            fingerprint: parsed.fingerprint,
          },
          prf,
          c.id,
        );
        if (prf) new Uint8Array(prf).fill(0);
        await api("/api/key/read/finish", {
          ceremony: start.ceremony,
          credential: publicCredential(c),
        });
        const save = await api("/api/key/write/begin", {
          name: form.keyName.value,
          fingerprint: parsed.fingerprint,
        });
        const written = await credential(save.options, false, blob);
        if (!written.getClientExtensionResults().largeBlob?.written)
          throw new Error(
            "Your passkey provider could not store this key. Its largeBlob capacity may be too small. No server copy was made.",
          );
        await api("/api/key/write/finish", {
          ceremony: save.ceremony,
          credential: publicCredential(written),
        });
        form.reset();
        await refresh();
        toast("SSH key saved to your device keychain.");
      } finally {
        key = "";
        passphrase = "";
        form.privateKey.value = "";
        form.passphrase.value = "";
      }
    });
  };
}
function renderClients() {
  chrome(`<div class="page-heading"><div><h1>CLI clients</h1><p>Pair the computers where Codex will request access.</p></div></div><div class="key-layout"><section><form id="client-form" class="form-card"><h2>Pair a CLI</h2><p>A paired client can request access. Every grant still needs your approval.</p><label for="client-name">Client name</label><input name="name" id="client-name" required maxlength="80" placeholder="Codex on my Mac"><button class="primary">Create pairing token</button></form><div id="pair-result"></div><div class="section-heading"><h2>Paired clients</h2><span>${state.clients.length} clients</span></div>${state.clients.length ? state.clients.map((c) => `<div class="client-row"><span class="terminal-icon">${icon("terminal")}</span><div><strong>${esc(c.name)}</strong><small>Paired ${esc(time(c.createdAt))}</small></div><button class="danger" data-remove-client="${esc(c.id)}">Remove</button></div>`).join("") : '<p class="muted">No CLI clients paired yet.</p>'}</section><aside class="side-panel"><h3>CLI commands</h3><p>Once paired, request access with a purpose and a time limit.</p><pre>remote-ssh-agent request \
  --session deploy-api \
  --reason 'Deploy the API fix' \
  --duration 15m</pre><p>The command waits for your approval and returns the socket path.</p><pre>remote-ssh-agent revoke \
  --session deploy-api</pre><p class="small">Use <code>ssh-config</code> to request approval automatically when connecting to an SSH host alias.</p></aside></div>`);
  document.querySelector("#client-form").onsubmit = (e) => {
    e.preventDefault();
    action(async () => {
      const result = await api("/api/clients", {
        name: e.target.elements.namedItem("name").value,
      });
      state = await api("/api/state");
      render();
      document.querySelector("#pair-result").innerHTML =
        `<div class="token-card"><h3>Copy your pairing token</h3><p>This token is shown once. On the CLI computer run the command below, paste the token, and press Ctrl-D.</p><pre>remote-ssh-agent configure \
  --server ${esc(location.origin)} --token-stdin</pre><label for="pair-token">Pairing token</label><input id="pair-token" readonly autocomplete="off" value="${esc(result.token)}"><button id="copy-token" class="secondary">Copy token</button><p class="small">Keep this token private. Removing the client invalidates it and revokes its sessions.</p></div>`;
      document.querySelector("#copy-token").onclick = () =>
        action(async () => {
          await navigator.clipboard.writeText(result.token);
          toast("Token copied.");
        });
    });
  };
  root.querySelectorAll("[data-remove-client]").forEach(
    (b) =>
      (b.onclick = () =>
        action(async () => {
          await api("/api/clients/" + b.dataset.removeClient, {}, "DELETE");
          await refresh();
          toast("Client removed and its sessions revoked.");
        })),
  );
}
async function refresh() {
  const opened = [...root.querySelectorAll("details[open]")].map(
    (el) => el.closest("[id]")?.id,
  );
  const focused = document.activeElement;
  const approval = focused?.dataset?.approve;
  const revoke = focused?.dataset?.revoke;
  state = await api("/api/state");
  render();
  for (const id of opened) {
    const detail = document.getElementById(id)?.querySelector("details");
    if (detail) detail.open = true;
  }
  if (approval)
    root
      .querySelector(`[data-approve="${CSS.escape(approval)}"]`)
      ?.focus({ preventScroll: true });
  if (revoke)
    root
      .querySelector(`[data-revoke="${CSS.escape(revoke)}"]`)
      ?.focus({ preventScroll: true });
}
async function start() {
  try {
    if ("serviceWorker" in navigator)
      navigator.serviceWorker.register("/sw.js").catch(() => {});
    info = await api("/api/info");
    if (!info.registered) {
      renderSetup();
      return;
    }
    try {
      await refresh();
    } catch (e) {
      if (!state) renderLogin();
      else throw e;
    }
  } catch (e) {
    root.innerHTML =
      '<section class="login-panel"><h1>Agent unavailable</h1><p>Check your connection, then reload to continue. Approvals are unavailable while offline.</p><button id="reload" class="primary">Try again</button></section>';
    document.querySelector("#reload").onclick = () => location.reload();
  }
}
setInterval(() => {
  if (
    state &&
    !busy &&
    tab === "requests" &&
    document.visibilityState === "visible"
  )
    refresh().catch((e) =>
      toast("Connection lost. No offline approvals are possible.", true),
    );
}, 4000);
setInterval(() => {
  if (state)
    root.querySelectorAll("[data-countdown]").forEach((el) => {
      const q = state.requests[el.dataset.countdown];
      if (q) el.textContent = countdown(q);
    });
}, 1000);
window.addEventListener("online", () => {
  if (state && !busy) refresh().catch(() => {});
});
start();
