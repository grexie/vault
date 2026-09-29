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
    const actual = args[0] === "grant" ? [args[0], args[1], "--config", config, ...args.slice(2)] : [args[0], "--config", options.config || config, ...args.slice(1)];
    const p = spawn(exe, actual, {
      ...options,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "",
      err = "";
    p.stdout.on("data", (b) => (out += b));
    p.stderr.on("data", (b) => (err += b));
    p.on("error", reject);
    p.stdin.on("error", e => { if (e.code !== "EPIPE") reject(e); });
    p.on("exit", (code) => resolve({ code, out, err }));
    if (options.input) p.stdin.write(options.input);
    p.stdin.end();
  });
}
let browser, sshFixture;
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
        const credential = await oldGet(...args);
        if (args[0].publicKey.extensions?.largeBlob?.read) {
          const outputs = credential.getClientExtensionResults();
          // Safari's native assertion path includes didWrite=false on reads.
          // Keep real assertions/PRF/blob storage, with only this output shape
          // adjusted to exercise the iPhone/iPad interoperability regression.
          Object.defineProperty(credential, "getClientExtensionResults", {
            value: () => ({
              ...outputs,
              largeBlob: { ...outputs.largeBlob, written: false },
            }),
          });
        }
        return credential;
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
  await page.route(
    "**/api/key/read/finish",
    (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: "Passkey verification failed" }),
      }),
    { times: 1 },
  );
  await page.getByRole("button", { name: "Save to device keychain" }).click();
  await page
    .locator("#message")
    .filter({ hasText: "Passkey verification failed" })
    .waitFor();
  assert.equal(
    await page.getByRole("heading", { name: "Your SSH key" }).isVisible(),
    true,
  );
  assert.equal(
    await page.getByLabel("SSH private key", { exact: true }).inputValue(),
    "",
  );
  assert.equal(
    await page.getByLabel("Existing key passphrase").inputValue(),
    "",
  );
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
  const document = "Synthetic age browser test document\n".repeat(5000);
  const encrypted = await cli(["encrypt", "--armor"], {input: document});
  assert.equal(encrypted.code, 0, encrypted.err);
  assert.match(encrypted.out, /^-----BEGIN AGE ENCRYPTED FILE-----/);
  assert.equal(await page.evaluate(async () => Object.keys((await (await fetch("/api/state")).json()).requests).length), 0);
  const oversized = await cli([
    "request", "--no-wait", "--session", "oversized-smoke",
    "--reason", "Verify the maximum lease is enforced",
    "--duration", "48h1s",
  ]);
  assert.notEqual(oversized.code, 0);
  assert.match(oversized.err, /1s–48h/);
  const requested = await cli([
    "request",
    "--no-wait",
    "--session",
    "browser-smoke",
    "--reason",
    "Verify approval with a generated RSA key",
    "--duration",
    "48h",
  ]);
  assert.equal(requested.code, 0, requested.err);
  const pending = JSON.parse(requested.out);
  assert.equal(pending.status, "pending");
  assert.equal(pending.durationSeconds, 48 * 60 * 60);
  const status = await cli(["status", "--session", "browser-smoke"]);
  assert.equal(JSON.parse(status.out).status, "pending");
  await page.getByRole("button", { name: /^Requests/ }).click();
  await page.getByRole("button", { name: "Approve for 48 hours" }).waitFor();
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
  await page.getByRole("button", { name: "Approve for 48 hours" }).click();
  const approved = await waiting;
  assert.equal(approved.code, 0, approved.err);
  const activeStatus = JSON.parse((await cli(["status", "--session", "browser-smoke"])).out);
  const remaining = (new Date(activeStatus.expiresAt) - Date.now()) / 1000;
  assert.ok(remaining > 48 * 60 * 60 - 120 && remaining <= 48 * 60 * 60);
  await until(async () => /^(47|48):\d{2}:\d{2}$/.test(
    await page.locator(`[data-countdown="${pending.id}"]`).textContent(),
  ));
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
  // Native SSH/SCP use the real config parser, transport, and agent signatures.
  execFileSync("go", ["build", "-o", "bin/sshd-fixture", "./scripts/sshd-fixture"]);
  const remoteDir = join(dir, "remote");
  await mkdir(remoteDir);
  sshFixture = spawn(resolve("bin/sshd-fixture"), [join(dir, "test.pub"), remoteDir]);
  let fixtureOut = "", fixtureErr = "";
  sshFixture.stdout.on("data", b => fixtureOut += b);
  sshFixture.stderr.on("data", b => fixtureErr += b);
  const fixture = await until(() => { if (sshFixture.exitCode !== null) throw new Error(fixtureErr); return fixtureOut.includes("\n") && JSON.parse(fixtureOut.trim()); });
  const knownHosts = join(dir, "known_hosts");
  await writeFile(knownHosts, `[127.0.0.1]:${fixture.port} ${fixture.hostKey}`);
  const nativeReason = "Verify SSH, SCP and jump routing: 100% 'native' approval";
  const snippet = await cli([
    "ssh-config", "--host", "fixture-host", "--hostname", "127.0.0.1",
    "--session", "config-smoke", "--reason", nativeReason, "--duration", "2m",
  ]);
  assert.equal(snippet.code, 0, snippet.err);
  const configPath = join(dir, "ssh.conf");
  const nativeConfig = snippet.out + snippet.out.replaceAll("fixture-host", "fixture-jump") + snippet.out.replaceAll("fixture-host", "fixture-via") + `
Host fixture-via
    ProxyJump fixture-jump
Host *
    Port ${fixture.port}
    User fixture
    BatchMode yes
    ConnectTimeout 5
    StrictHostKeyChecking yes
    UserKnownHostsFile "${knownHosts}"
`;
  await writeFile(configPath, nativeConfig);
  function native(command, args, input = "", socket = "") {
    return new Promise((resolve, reject) => {
      const p = spawn(`/usr/bin/${command}`, ["-F", configPath, ...args], {
        env: {...process.env, SSH_AUTH_SOCK: socket}, stdio:["pipe","pipe","pipe"],
      });
      let out = "", err = "";
      const timer = setTimeout(() => { p.kill(); reject(new Error(`native ${command} ${args.join(" ")} timed out: ${err}`)); }, 35000);
      p.stdout.on("data", b => out += b);
      p.stderr.on("data", b => err += b);
      p.on("error", reject);
      p.stdin.on("error", e => { if (e.code !== "EPIPE") reject(e); });
      p.on("close", code => { clearTimeout(timer); resolve({code,out,err}); });
      p.stdin.end(input);
    });
  }
  const stdinFixture = "Native SSH keeps stdin, including spaces and newlines.\n";
  const nativeSSH = native("ssh", ["-T", "fixture-host", "cat; printf 'native-stderr' >&2; exit 37"], stdinFixture);
  await until(async () => {
    if (!(await page.locator(".busy").count())) await page.getByRole("button", { name: /^Requests/ }).click();
    return await page.getByRole("button", { name: "Approve for 2 min" }).isVisible();
  }, 20000);
  await page.getByRole("button", { name: "Approve for 2 min" }).click();
  const nativeResult = await nativeSSH;
  assert.equal(nativeResult.code, 37, nativeResult.err);
  assert.equal(nativeResult.out, stdinFixture);
  assert.match(nativeResult.err, /native-stderr/);
  const parsedSSH = await native("ssh", ["-G", "fixture-host"]);
  assert.equal(parsedSSH.code, 0, parsedSSH.err);
  assert.match(parsedSSH.out, /identityagent .*\.sock/);
  assert.doesNotMatch(parsedSSH.out, /^controlpath (?!none$).+/m);
  assert.match(parsedSSH.out, /controlmaster (false|no)/);
  const viaJump = await native("ssh", ["fixture-via", "printf jump-ok"]);
  assert.equal(viaJump.code, 0, viaJump.err);
  assert.equal(viaJump.out, "jump-ok");
  const upload = join(dir, "upload with spaces.txt"), download = join(dir, "download.txt");
  await writeFile(upload, stdinFixture);
  for (const legacy of [false, true]) {
    const options = legacy ? ["-O"] : [];
    const remoteName = legacy ? "legacy.txt" : "uploaded with spaces.txt";
    const sent = await native("scp", [...options, "-p", upload, `fixture-host:${remoteName}`]);
    assert.equal(sent.code, 0, sent.err);
    const received = await native("scp", [...options, `fixture-host:${remoteName}`, download]);
    assert.equal(received.code, 0, received.err);
    assert.equal(await readFile(download, "utf8"), stdinFixture);
  }
  const tree = join(dir,"tree");
  await mkdir(tree);
  await writeFile(join(tree,"nested.txt"), stdinFixture);
  const recursive = await native("scp", ["-r", tree, "fixture-via:copied-tree"]);
  assert.equal(recursive.code, 0, recursive.err);
  assert.equal(await readFile(join(remoteDir,"copied-tree","nested.txt"),"utf8"), stdinFixture);
  const originalLease = JSON.parse((await cli(["status", "--session", "config-smoke"])).out);
  // A task's explicit approved socket wins over the host's static reason without a new prompt.
  await writeFile(configPath, nativeConfig.replaceAll("config-smoke", "unused-host-session"));
  const inheritedSSH = await native("ssh", ["fixture-host", "printf inherited-ok"], "", originalLease.socket);
  assert.equal(inheritedSSH.code, 0, inheritedSSH.err);
  assert.equal(inheritedSSH.out, "inherited-ok");
  assert.notEqual((await cli(["status", "--session", "unused-host-session"])).code, 0);
  // A mismatched reason must not authenticate through the still-active alias.
  await writeFile(configPath, nativeConfig.replaceAll("2m0s", "3m0s"));
  const mismatch = await native("ssh", ["fixture-host", "printf must-not-run"]);
  assert.notEqual(mismatch.code, 0);
  assert.equal(mismatch.out, "");
  assert.match(mismatch.err, /different access, justification, or duration/);
  assert.equal((await cli(["revoke", "--session", "config-smoke"])).code, 0);
  await writeFile(configPath, nativeConfig);
  const revokedInherited = await native("ssh", ["fixture-host", "printf must-not-run"], "", originalLease.socket);
  assert.notEqual(revokedInherited.code, 0);
  assert.equal(revokedInherited.out, "");
  // Denial blocks both transport and any local-key fallback.
  const deniedSSH = native("ssh", ["fixture-host", "printf must-not-run"]);
  await until(async () => {
    await page.getByRole("button", { name: /^Requests/ }).click();
    return await page.getByRole("button", { name: "Deny", exact: true }).isVisible();
  });
  await page.getByRole("button", { name: "Deny", exact: true }).click();
  const deniedNative = await deniedSSH;
  assert.notEqual(deniedNative.code, 0);
  assert.equal(deniedNative.out, "");
  assert.match(deniedNative.err, /denied/);
  assert.equal((await cli(["revoke", "--session", "config-smoke"])).code, 0);
  console.log("PASS: native SSH, SCP SFTP/legacy/recursive transfers, jump hosts, inherited approval, mismatch and rejection.");
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
  // File headers alone travel to Sentinel; plaintext and body stay local.
  const single = cli(["decrypt", "--reason", "Read this one generated browser document", "--timeout", "30s"], {input: encrypted.out});
  await page.getByRole("button", {name: "Decrypt once", exact: true}).waitFor();
  await page.getByRole("button", {name: "Decrypt once", exact: true}).click();
  const singleResult = await single;
  assert.equal(singleResult.code, 0, singleResult.err);
  assert.equal(singleResult.out, document);
  const singleState = await page.evaluate(async () => (await (await fetch("/api/state")).json()).requests);
  const singleRequest = Object.values(singleState).find(q => q.mode === "age-once");
  assert.equal(singleRequest.status, "completed");
  assert.equal(singleRequest.socket, "");
  assert.equal(singleRequest.durationSeconds, 0);
  const ageLease = await cli(["request", "--no-wait", "--session", "age-smoke", "--reason", "Read generated documents with a scoped age lease", "--access", "age", "--duration", "60s"]);
  assert.equal(ageLease.code,0,ageLease.err);
  const ageWait = cli(["wait", "--session", "age-smoke", "--timeout", "30s"]);
  await page.getByRole("button", {name: "Approve for 1 min", exact:true}).waitFor();
  await page.getByRole("button", {name: "Approve for 1 min", exact:true}).click();
  assert.equal((await ageWait).code,0);
  const ageResult = await cli(["decrypt", "--session", "age-smoke"], {input: encrypted.out});
  assert.equal(ageResult.code,0,ageResult.err);
  assert.equal(ageResult.out,document);
  assert.equal((await cli(["revoke", "--session", "age-smoke"])).code,0);
  assert.notEqual((await cli(["decrypt", "--session", "age-smoke"], {input: encrypted.out})).code,0);

  // CI clients need only a connection token, not a paired-client config or key.
  const grant = await cli(["grant", "create", "--no-wait", "--session", "ci-smoke", "--reason", "Test GitHub ephemeral runner access", "--idle-timeout", "5s"]);
  assert.equal(grant.code,0,grant.err);
  const grantID = JSON.parse(grant.out).id;
  await page.getByRole("button", {name: "Approve persistent access", exact:true}).waitFor();
  await page.getByRole("button", {name: "Approve persistent access", exact:true}).click();
  await until(async () => JSON.parse((await cli(["status", "--session", "ci-smoke"])).out).status === "active");
  const exported = await cli(["grant", "export", "--session", "ci-smoke", "--token-stdout"]);
  assert.equal(exported.code,0,exported.err);
  const ciConfig = join(dir,"ci-a.json");
  const connected = await cli(["connect", "--session", "ci-job-a", "--token-stdin", "--duration", "60s"], {input: exported.out, config: ciConfig});
  assert.equal(connected.code,0,connected.err);
  const ciSocket = connected.out.trim();
  execFileSync("/usr/bin/ssh-add", ["-T", join(dir,"test.pub")], {env:{...process.env, SSH_AUTH_SOCK:ciSocket}});
  await until(async () => JSON.parse((await cli(["status", "--session", "ci-smoke"])).out).status === "locked",15000);
  const reconnected = cli(["connect", "--session", "ci-job-b", "--token-stdin", "--duration", "60s", "--timeout", "30s"], {input:exported.out,config:join(dir,"ci-b.json")});
  await page.locator(`#request-${grantID}`).getByRole("button", {name:"Unlock grant",exact:true}).waitFor();
  await page.locator(`#request-${grantID}`).getByRole("button", {name:"Unlock grant",exact:true}).click();
  const resumed = await reconnected;
  assert.equal(resumed.code,0,resumed.err);
  assert.notEqual(resumed.out.trim(),ciSocket);
  execFileSync("/usr/bin/ssh-add", ["-T", join(dir,"test.pub")], {env:{...process.env, SSH_AUTH_SOCK:resumed.out.trim()}});
  await page.screenshot({path:"test-results/phone-persistent-grant.png",fullPage:true});
  await page.locator(`#request-${grantID}`).getByRole("button", {name:"Revoke access",exact:true}).click();
  const cannotReconnect = await cli(["connect", "--session", "ci-job-c", "--token-stdin"], {input:exported.out,config:join(dir,"ci-c.json")});
  assert.notEqual(cannotReconnect.code,0);
  assert.match(cannotReconnect.err,/Invalid connection token/);
  await until(async()=>{try{await import("node:fs/promises").then(fs=>fs.stat(resumed.out.trim()));return false}catch(e){return e.code === "ENOENT"}},5000);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await page.getByRole("heading", { name: "Sign in", exact: true }).waitFor();
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await page.getByRole("heading", { name: "Requests", exact: true }).waitFor();
  assert.deepEqual(errors, []);
  console.log(
    "PASS: unattended age encryption, scoped and one-shot decryption, persistent CI connection token, idle auto-lock, reapproval with unchanged token, grant revocation, real WebAuthn PRF/largeBlob virtual authenticator, encrypted RSA paste, local Wasm validation, PWA approval, CLI submit/status/wait, ssh-add signatures, live phone revocation, rejection, expiry, wait timeout, automatic exec cleanup, native SSH stdin and exit status, SCP SFTP/legacy/recursive transfers, ProxyJump, inherited task leases, fail-closed SSH config, responsive layouts.",
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
  if (sshFixture && sshFixture.exitCode === null && sshFixture.signalCode === null) { sshFixture.kill(); await new Promise(r => sshFixture.once("exit",r)); }
  server.kill("SIGTERM");
  await new Promise((r) => server.once("exit", r));
  await rm(dir, { recursive: true, force: true });
}
