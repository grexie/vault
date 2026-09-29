// End-to-end smoke test. Uses only generated fixtures and a virtual authenticator.
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { generateKeyPairSync } from "node:crypto";
import assert from "node:assert/strict";
const { chromium } = await import(
  process.env.PLAYWRIGHT_MODULE || "playwright"
);
const dir = await mkdtemp(join(tmpdir(), "remote-ssh-smoke-"));
const exe = resolve("bin/remote-ssh-agent");
const listener = createServer();
await new Promise((r) => listener.listen(0, "127.0.0.1", r));
const port = listener.address().port;
await new Promise((r) => listener.close(r));
const origin = "http://localhost:" + port,
  config = join(dir, "cli.json");
const server = spawn(
  exe,
  [
    "serve",
    "--origin",
    origin,
    "--listen",
    "127.0.0.1:" + port,
    "--data",
    join(dir, "data"),
  ],
  { stdio: ["ignore", "pipe", "pipe"] },
);
let logs = "";
server.stderr.on("data", (b) => (logs += b.toString()));
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, timeout = 15000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      last = e;
    }
    await delay(100);
  }
  throw last || new Error("condition timed out");
}
async function cli(args, options = {}) {
  return await new Promise((resolve, reject) => {
    const p = spawn(exe, [args[0], "--config", config, ...args.slice(1)], {
      ...options,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "",
      err = "";
    p.stdout.on("data", (b) => (out += b));
    p.stderr.on("data", (b) => (err += b));
    p.on("error", reject);
    p.on("exit", (code) => resolve({ code, out, err }));
    if (options.input) p.stdin.write(options.input);
    p.stdin.end();
  });
}
let browser;
const errors = [];
try {
  await until(() => logs.includes("one-time setup token:"));
  const token = logs.match(/one-time setup token: (\S+)/)[1];
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1365, height: 1000 },
  });
  const page = await context.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasLargeBlob: true,
      hasPrf: true,
    },
  });
  await page.addInitScript(() => {
    const oldGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (...args) => {
      try {
        return await oldGet(...args);
      } catch (e) {
        console.error("AUTHENTICATOR_ERROR", e.name, e.message);
        throw e;
      }
    };
  });
  page.on("console", (m) => {
    if (m.type() === "error") console.error(m.text());
  });
  await page.goto(origin);
  await page.getByLabel("One-time setup token").fill(token);
  await page.getByRole("button", { name: "Create a passkey" }).click();
  await page
    .getByLabel("SSH private key", { exact: true })
    .waitFor({ timeout: 15000 });
  const passphrase = "synthetic-fixture-password";
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    privateKeyEncoding: {
      type: "pkcs1",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase,
    },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  await page
    .getByLabel("Key name", { exact: true })
    .fill("Generated test RSA key");
  await page.getByLabel("SSH private key", { exact: true }).fill(privateKey);
  await page.getByLabel("Existing key passphrase").fill(passphrase);
  await page.getByRole("button", { name: "Save to device keychain" }).click();
  await page
    .getByText("Key connected", { exact: true })
    .waitFor({ timeout: 30000 });
  assert.equal(
    await page.getByLabel("SSH private key", { exact: true }).inputValue(),
    "",
  );
  await page.getByRole("button", { name: "CLI clients", exact: true }).click();
  await page.getByLabel("Client name").fill("Codex smoke client");
  await page.getByRole("button", { name: "Create pairing token" }).click();
  await page.getByLabel("Pairing token", { exact: true }).waitFor();
  const pairing = await page
    .getByLabel("Pairing token", { exact: true })
    .inputValue();
  const configured = await cli(
    ["configure", "--server", origin, "--token-stdin"],
    { input: pairing },
  );
  assert.equal(configured.code, 0, configured.err);
  const requested = await cli([
    "request",
    "--no-wait",
    "--session",
    "browser-smoke",
    "--reason",
    "Verify approval with a generated RSA key",
    "--duration",
    "30s",
  ]);
  assert.equal(requested.code, 0, requested.err);
  const pending = JSON.parse(requested.out);
  assert.equal(pending.status, "pending");
  const status = await cli(["status", "--session", "browser-smoke"]);
  assert.equal(JSON.parse(status.out).status, "pending");
  await page.getByRole("button", { name: /^Requests/ }).click();
  await page.getByRole("button", { name: "Approve for 30 sec" }).waitFor();
  await mkdir("test-results", { recursive: true });
  await page.screenshot({
    path: "test-results/desktop-requests.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({
    path: "test-results/phone-requests.png",
    fullPage: true,
  });
  assert.ok(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  );
  const waiting = cli([
    "wait",
    "--session",
    "browser-smoke",
    "--timeout",
    "45s",
  ]);
  await page.getByRole("button", { name: "Approve for 30 sec" }).click();
  const approved = await waiting;
  assert.equal(approved.code, 0, approved.err);
  const socket = approved.out.trim();
  assert.ok(socket.endsWith("/agent.sock"));
  const pub = execFileSync("/usr/bin/ssh-add", ["-L"], {
    env: { ...process.env, SSH_AUTH_SOCK: socket },
    encoding: "utf8",
  });
  assert.match(pub, /^ssh-rsa /);
  await writeFile(join(dir, "test.pub"), pub);
  execFileSync("/usr/bin/ssh-add", ["-T", join(dir, "test.pub")], {
    env: { ...process.env, SSH_AUTH_SOCK: socket },
  });
  // Keep an agent protocol connection open across phone revocation.
  const connection = await import("node:net").then((m) =>
    m.createConnection(socket),
  );
  await new Promise((r) => connection.once("connect", r));
  let closed = false;
  connection.on("close", () => (closed = true));
  connection.on("error", () => {});
  await page.getByRole("button", { name: "Revoke access" }).click();
  await until(() => closed, 10000);
  const revoked = await cli(["status", "--session", "browser-smoke"]);
  assert.equal(JSON.parse(revoked.out).status, "revoked");
  // Independent nonblocking request, then rejection observed by wait.
  assert.equal(
    (
      await cli([
        "request",
        "--no-wait",
        "--session",
        "reject-smoke",
        "--reason",
        "Exercise a user rejection response",
        "--duration",
        "30s",
      ])
    ).code,
    0,
  );
  await until(async () => {
    await page.getByRole("button", { name: /^Requests/ }).click();
    return await page
      .getByRole("button", { name: "Deny", exact: true })
      .isVisible();
  });
  const rejectedWait = cli(["wait", "--session", "reject-smoke"]);
  await page.getByRole("button", { name: "Deny", exact: true }).click();
  const rejection = await rejectedWait;
  assert.notEqual(rejection.code, 0);
  assert.match(rejection.err, /denied/);
  // Auto-request integration uses a real OpenSSH config parser (ssh -G evaluates Match exec).
  const snippet = await cli([
    "ssh-config",
    "--host",
    "fixture-host",
    "--hostname",
    "example.invalid",
    "--session",
    "config-smoke",
    "--reason",
    "Verify the configured SSH host approval",
    "--duration",
    "30s",
  ]);
  assert.equal(snippet.code, 0, snippet.err);
  const configPath = join(dir, "ssh.conf");
  await writeFile(configPath, snippet.out);
  const ssh = spawn("/usr/bin/ssh", ["-F", configPath, "-G", "fixture-host"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let sshOut = "",
    sshErr = "";
  ssh.stdout.on("data", (b) => (sshOut += b));
  ssh.stderr.on("data", (b) => (sshErr += b));
  const sshExit = new Promise((r) => ssh.on("exit", r));
  await until(async () => {
    if (!(await page.locator(".busy").count()))
      await page.getByRole("button", { name: /^Requests/ }).click();
    return await page
      .getByRole("button", { name: "Approve for 30 sec" })
      .isVisible();
  }, 20000);
  await page.getByRole("button", { name: "Approve for 30 sec" }).click();
  assert.equal(await sshExit, 0, sshErr);
  assert.match(sshOut, /identityagent .*\.sock/);
  assert.equal((await cli(["revoke", "--session", "config-smoke"])).code, 0);
  // Timeout cancels a still-pending request instead of leaving a surprise grant.
  assert.equal(
    (
      await cli([
        "request",
        "--no-wait",
        "--session",
        "timeout-smoke",
        "--reason",
        "Verify pending-request cancellation",
        "--duration",
        "30s",
      ])
    ).code,
    0,
  );
  const timed = await cli([
    "wait",
    "--session",
    "timeout-smoke",
    "--timeout",
    "200ms",
  ]);
  assert.notEqual(timed.code, 0);
  assert.equal(
    JSON.parse((await cli(["status", "--session", "timeout-smoke"])).out)
      .status,
    "revoked",
  );
  // A live bridge removes its socket at the same fixed expiry without CLI cleanup.
  assert.equal(
    (
      await cli([
        "request",
        "--no-wait",
        "--session",
        "expire-smoke",
        "--reason",
        "Verify the socket lifetime boundary",
        "--duration",
        "3s",
      ])
    ).code,
    0,
  );
  await until(async () => {
    await page.getByRole("button", { name: /^Requests/ }).click();
    return await page
      .getByRole("button", { name: "Approve for 3 sec" })
      .isVisible();
  });
  const expiryWait = cli(["wait", "--session", "expire-smoke"]);
  await page.getByRole("button", { name: "Approve for 3 sec" }).click();
  const expiring = await expiryWait;
  assert.equal(expiring.code, 0, expiring.err);
  await until(
    async () =>
      JSON.parse((await cli(["status", "--session", "expire-smoke"])).out)
        .status === "expired",
    8000,
  );
  await until(async () => {
    try {
      await import("node:fs/promises").then((fs) =>
        fs.stat(expiring.out.trim()),
      );
      return false;
    } catch (e) {
      return e.code === "ENOENT";
    }
  }, 4000);
  // The one-command wrapper revokes on successful child completion.
  const wrapped = cli([
    "exec",
    "--session",
    "exec-smoke",
    "--reason",
    "Verify automatic session cleanup",
    "--duration",
    "30s",
    "--",
    "/usr/bin/true",
  ]);
  await until(async () => {
    await page.getByRole("button", { name: /^Requests/ }).click();
    return await page
      .getByRole("button", { name: "Approve for 30 sec" })
      .isVisible();
  });
  await page.getByRole("button", { name: "Approve for 30 sec" }).click();
  const executed = await wrapped;
  assert.equal(executed.code, 0, executed.err);
  const serverState = await page.evaluate(
    async () => await (await fetch("/api/state")).json(),
  );
  assert.equal(
    Object.values(serverState.requests).find((q) => q.session === "exec-smoke")
      .status,
    "revoked",
  );
  assert.deepEqual(errors, []);
  console.log(
    "PASS: real WebAuthn PRF/largeBlob virtual authenticator, encrypted RSA paste, local Wasm validation, PWA approval, CLI submit/status/wait, ssh-add signatures, live phone revocation, rejection, expiry, wait timeout, automatic exec cleanup, ssh-config auto-request, responsive layouts.",
  );
} catch (e) {
  if (browser) {
    const pages = browser.contexts().flatMap((c) => c.pages());
    if (pages[0])
      console.error(
        "Page status:",
        await pages[0]
          .locator("#message")
          .textContent()
          .catch(() => ""),
        await pages[0]
          .locator("h1")
          .textContent()
          .catch(() => ""),
      );
  }
  throw e;
} finally {
  if (browser) await browser.close();
  server.kill("SIGTERM");
  await new Promise((r) => server.once("exit", r));
  await rm(dir, { recursive: true, force: true });
}
