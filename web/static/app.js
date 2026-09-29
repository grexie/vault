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
  root.innerHTML = `<div class="welcome"><div class="eyebrow">YOUR PERSONAL ACCESS DESK</div><h1>SSH access.<br><span>With your permission.</span></h1><p class="intro">Approve a session from your phone. Your key stays in your device’s passkey storage until you unlock it.</p><div class="setup-card"><div class="step-number">01</div><div><h2>Connect your keychain</h2><p>Create a passkey in your device’s password manager. Your provider must support encryption and key storage.</p><form id="setup"><label for="setup-token">One-time setup token</label><input id="setup-token" name="token" autocomplete="off" type="password" required placeholder="From the server’s first startup"><button class="primary" type="submit">Create a passkey <span aria-hidden="true">${icon("key")}</span></button></form><p class="small">Setup checks WebAuthn PRF and largeBlob. Keychain sync depends on your passkey provider; test another device before relying on recovery.</p></div></div></div><aside class="welcome-aside"><div class="signal-circle">${icon("lock")}</div><p class="eyebrow">LOCKED BY DEFAULT</p><h2>You approve the purpose.<br>You set the limit.</h2><ul class="principles"><li><span>01</span>A reason for every request</li><li><span>02</span>A separate socket per session</li><li><span>03</span>Revoke access at any time</li></ul></aside>`;
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
  root.innerHTML = `<section class="login-panel"><div class="eyebrow">REMOTE SSH AGENT</div><div class="signal-circle">${icon("lock")}</div><h1>Your access desk.</h1><p>Sign in with the passkey you saved in your device’s keychain.</p><button id="login" class="primary">Sign in with a passkey</button><p class="small">Each SSH approval requires a separate verification.</p></section>`;
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
    `<div class="page-heading"><div><div class="eyebrow">ACCESS CONTROL</div><h1>Session requests</h1><p>Only the access you approve, only for as long as you allow.</p></div><button id="notifications" class="secondary">${icon("phone")} Enable notifications</button></div>${!state.key.fingerprint ? '<div class="notice">Connect your SSH key in <button id="open-keychain" class="text-button">Keychain</button> before requesting access.</div>' : ""}<div class="summary-strip"><div><strong>${String(pending.length).padStart(2, "0")}</strong><span>Awaiting approval</span></div><div><strong>${String(active.length).padStart(2, "0")}</strong><span>Active sessions</span></div><div class="key-summary"><span class="square-icon">${icon("key")}</span><span>${esc(state.key.name || "No SSH key yet")}<small>${state.key.fingerprint ? "Saved with your passkey" : "Keychain setup needed"}</small></span></div></div><div class="request-layout"><div><div class="section-heading"><h2>Needs your approval</h2><span>${pending.length} pending</span></div>${pending.length ? pending.map((q) => requestCard(q)).join("") : `<div class="empty"><span class="empty-icon">${icon("check")}</span><h3>All quiet here</h3><p>When Codex requests SSH access, you’ll see the session, reason, and time limit here.</p><code>remote-ssh-agent request</code></div>`}<div class="section-heading active-heading"><h2>Active sessions</h2><span>${active.length} unlocked</span></div>${active.length ? active.map((q) => requestCard(q)).join("") : '<p class="muted empty-inline">No keys are currently unlocked.</p>'}</div><aside class="side-panel"><div class="eyebrow">YOUR KEYCHAIN</div><div class="key-illustration">${icon("lock")}</div><h3>Locked until you say so.</h3><p>Every approval needs your passkey. Access expires automatically, and you can end it sooner.</p><hr><div class="side-label">NOTIFICATIONS</div><p>${state.pushSubscriptions ? "A notification device is connected." : "Add this app to your Home Screen, open it, then enable notifications."}</p><div class="small">Revoking prevents new authentication. Existing SSH connections remain connected.</div></aside></div>${
      history.length
        ? `<div class="section-heading"><h2>Recent activity</h2><span>Last ${Math.min(history.length, 10)} sessions</span></div><div class="history">${history
            .slice(0, 10)
            .map(
              (q) =>
                `<div class="history-row"><span class="terminal-icon">${icon("terminal")}</span><div><strong>${esc(q.session)}</strong><small>${esc(q.clientName)} · ${esc(time(q.createdAt))}</small></div><span class="badge ${esc(q.status)}">${esc(q.status)}</span></div>`,
            )
            .join("")}</div>`
        : ""
    }`,
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
  return `<article class="request-card ${pending ? "pending-card" : "active-card"}" id="request-${esc(q.id)}"><div class="request-top"><span class="terminal-icon">${icon("terminal")}</span><div><h3>${esc(q.session)}</h3><p>${esc(q.clientName)}</p></div><span class="badge ${pending ? "pending" : "active"}">${pending ? "Needs approval" : "Active"}</span></div><div class="reason-label">REQUESTED PURPOSE</div><p class="reason">${esc(q.reason)}</p><div class="request-details"><span>${icon("clock")} ${minutes(q.durationSeconds)}</span><span>${esc(q.keyName)}</span><span class="remaining">${pending ? "Approve within" : "Expires in"} <b data-countdown="${esc(q.id)}">${countdown(q)}</b></span></div><details><summary>Connection details</summary><dl><dt>Fingerprint</dt><dd>${esc(q.fingerprint)}</dd><dt>Requested socket</dt><dd>${esc(q.socket)}</dd><dt>Request ID</dt><dd>${esc(q.id)}</dd></dl><p class="small">The session name, purpose, and socket path were supplied by this CLI client.</p></details><div class="request-actions">${pending ? `<button class="secondary" data-revoke="${esc(q.id)}">Deny</button><button class="primary" data-approve="${esc(q.id)}">Approve for ${minutes(q.durationSeconds)} <span>${icon("key")}</span></button>` : `<span class="small">${esc(time(q.expiresAt))} expiry</span><button class="danger" data-revoke="${esc(q.id)}">Revoke access</button>`}</div></article>`;
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
    `<div class="page-heading"><div><div class="eyebrow">DEVICE KEYCHAIN</div><h1>Your SSH key</h1><p>Encrypted with your passkey. Stored with your device’s credential.</p></div><span class="badge ${state.key.fingerprint ? "active" : "pending"}">${state.key.fingerprint ? "Key connected" : "Setup needed"}</span></div><div class="key-layout"><form id="key-form" class="form-card"><h2>${state.key.fingerprint ? "Replace your saved key" : "Paste an existing key"}</h2><p>Paste the complete private key, including its BEGIN and END lines. Encrypted OpenSSH and PEM / PKCS#8 keys are supported.</p><label for="key-name">Key name</label><input name="keyName" id="key-name" required maxlength="80" value="${esc(state.key.name)}" placeholder="Personal SSH key"><label for="private-key">SSH private key</label><textarea name="privateKey" id="private-key" required spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" rows="9" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;Paste your private key here&#10;-----END OPENSSH PRIVATE KEY-----"></textarea><label for="key-passphrase">Existing key passphrase <span class="optional">if encrypted</span></label><input name="passphrase" id="key-passphrase" type="password" autocomplete="off" placeholder="The password that currently protects this key"><p class="small">The key is unlocked locally with its current passphrase, then re-encrypted with your passkey. The old passphrase is not saved. Two passkey prompts encrypt and save the key. ${state.key.fingerprint ? "Replacing the key revokes all open requests." : ""}</p><button class="primary" type="submit">${icon("key")} Save to device keychain</button></form><aside class="side-panel"><div class="eyebrow">STORAGE BOUNDARY</div><h3>The key belongs with you.</h3><p>The server keeps your key’s name and fingerprint. It does not store the private key, passphrase, or encrypted keychain blob.</p>${state.key.fingerprint ? `<div class="fingerprint"><span>Saved fingerprint</span><code>${esc(state.key.fingerprint)}</code></div>` : ""}<hr><h3>Keep your original key.</h3><p>Keychain storage limits and sync vary by provider. Confirm that the key is available on another device before depending on sync for recovery.</p><p class="small">An approval unlocks the key in a separate signer process on your server for that request’s lifetime.</p></aside></div>`,
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
  chrome(`<div class="page-heading"><div><div class="eyebrow">REQUEST SOURCES</div><h1>CLI clients</h1><p>Pair the computers where Codex will request access.</p></div></div><div class="key-layout"><section><form id="client-form" class="form-card"><h2>Pair a CLI</h2><p>A paired client can request access. Every grant still needs your approval.</p><label for="client-name">Client name</label><input name="name" id="client-name" required maxlength="80" placeholder="Codex on my Mac"><button class="primary">Create pairing token</button></form><div id="pair-result"></div><div class="section-heading"><h2>Paired clients</h2><span>${state.clients.length} clients</span></div>${state.clients.length ? state.clients.map((c) => `<div class="client-row"><span class="terminal-icon">${icon("terminal")}</span><div><strong>${esc(c.name)}</strong><small>Paired ${esc(time(c.createdAt))}</small></div><button class="danger" data-remove-client="${esc(c.id)}">Remove</button></div>`).join("") : '<p class="muted">No CLI clients paired yet.</p>'}</section><aside class="side-panel"><div class="eyebrow">FROM THE TERMINAL</div><h3>A socket for each session.</h3><p>Once paired, request access with a purpose and a time limit.</p><pre>remote-ssh-agent request \
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
  state = await api("/api/state");
  render();
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
