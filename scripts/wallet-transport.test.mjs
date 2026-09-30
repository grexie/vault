// Independent transport regressions. Run: node --test scripts/wallet-transport.test.mjs
// Compile the real TypeScript in memory; no browser, network, keys or native host
// is used. These adversarial boundary tests complement the real Chrome smoke test.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {transformSync} from 'esbuild';

const ORIGIN = 'https://dapp.example';
const OTHER = 'https://other.example';
const POPUP = 'chrome-extension://fixture-extension/popup.html';
const ADDRESS = '0x' + '1'.repeat(40);
const PARAM_LIMIT = 180 * 1024;
const sources = new Map(['provider', 'content', 'worker'].map(name => [name,
  transformSync(readFileSync(new URL(`../extension/src/${name}.ts`, import.meta.url), 'utf8'), {
    loader: 'ts', format: 'iife', define: {VAULT_ICON: '"data:image/png;base64,AA=="'},
  }).code,
]));
const plain = value => JSON.parse(JSON.stringify(value));
const settle = () => new Promise(resolve => setImmediate(resolve));

function signal() {
  const listeners = [];
  return {
    addListener(fn) { listeners.push(fn); },
    emit(...args) { return listeners.map(fn => fn(...args)); },
  };
}

function port() {
  return {
    name: 'vault-provider-v1', sent: [], disconnected: false,
    onMessage: signal(), onDisconnect: signal(),
    postMessage(message) { this.sent.push(message); },
    disconnect() { this.disconnected = true; this.onDisconnect.emit(); },
  };
}

function runtimeGlobals() {
  let sequence = 0;
  const timers = new Map();
  return {
    TextEncoder, URL, timers,
    crypto: {randomUUID() { return `transport-fixture-${++sequence}`; }},
    setTimeout(fn) { const id = ++sequence; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval() {},
  };
}

function pageFixture(name) {
  const listeners = new Map(), posted = [], contentPort = port();
  const window = {
    addEventListener(name, fn) {
      const list = listeners.get(name) || [];
      list.push(fn); listeners.set(name, list);
    },
    postMessage(message, origin) { posted.push({message, origin}); },
    dispatchEvent(event) {
      for (const fn of listeners.get(event.type) || []) fn(event);
    },
  };
  const globals = {
    ...runtimeGlobals(), window, location: {origin: ORIGIN},
    Event: class { constructor(type) { this.type = type; } },
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
    chrome: {runtime: {connect() { return contentPort; }}},
  };
  vm.runInNewContext(sources.get(name), globals, {filename: `${name}.ts`});
  return {
    window, posted, contentPort, globals, provider: window.grexieVault,
    receive(message, overrides = {}) {
      window.dispatchEvent({type: 'message', source: window, origin: ORIGIN,
        data: {target: `grexie-vault:${name === 'content' ? 'content' : 'page'}`, version: 1, ...message},
        ...overrides});
    },
  };
}

function workerFixture(tab = {id: 7}, {hold = []} = {}) {
  const nativeCalls = [], onConnect = signal(), onMessage = signal();
  const native = port();
  const state = {connected: false, permission: null,
    chain: {chainId: '0x1', chainName: 'Ethereum'}, vaultURL: 'https://private-vault.example/app/'};
  native.postMessage = q => {
    nativeCalls.push(q);
    if (q.cancel || hold.includes(q.method)) return;
    queueMicrotask(() => native.onMessage.emit({id: q.id,
      result: q.method === '_state' ? state : q.method === 'eth_chainId' ? '0x1' : 'fixture-response'}));
  };
  const globals = {
    ...runtimeGlobals(),
    chrome: {
      runtime: {id: 'fixture-extension', onConnect, onMessage,
        connectNative(name) { assert.equal(name, 'com.grexie.vault'); return native; },
        getURL(path) { return `chrome-extension://fixture-extension/${path}`; }},
      tabs: {async query(query) { assert.deepEqual(plain(query), {active: true, currentWindow: true}); return tab ? [tab] : []; }},
    },
  };
  vm.runInNewContext(sources.get('worker'), globals, {filename: 'worker.ts'});
  return {
    nativeCalls,
    connect(tabId = 7, origin = ORIGIN, overrides = {}) {
      const p = port();
      p.sender = {id: 'fixture-extension', frameId: 0, tab: {id: tabId, url: origin},
        url: origin, origin, ...overrides};
      onConnect.emit(p);
      return p;
    },
    popup(action = 'status', extra = {}, sender = {id: 'fixture-extension', url: POPUP}) {
      return new Promise(resolve => {
        const accepted = onMessage.emit({action, ...extra}, sender, resolve);
        if (!accepted.includes(true)) resolve({ignored: true});
      });
    },
  };
}

const invalidMethods = ['', 'eth_🔒', 'personal_ѕign', 'eth_chainId\n',
  'eth_chainId/extra', '_state', '_changeIdentity', 'eth_' + 'x'.repeat(77)];
const oversizedParams = [
  ['a'.repeat(PARAM_LIMIT)],
  ['🔒'.repeat(60000)],
];

test('provider rejects oversized UTF-8 and invalid methods before page transport', async () => {
  const f = pageFixture('provider');
  // The original UTF-16 .length check accepted this message even though its
  // encoded native frame exceeded the host's byte limit.
  assert(JSON.stringify(oversizedParams[1]).length < PARAM_LIMIT);
  assert(new TextEncoder().encode(JSON.stringify(oversizedParams[1])).byteLength > PARAM_LIMIT);
  for (const method of invalidMethods) {
    await assert.rejects(f.provider.request({method, params: []}), e => e.code === 4200, method);
  }
  for (const params of oversizedParams) {
    await assert.rejects(f.provider.request({method: 'personal_sign', params}), e => e.code === -32602);
  }
  const circular = []; circular.push(circular);
  await assert.rejects(f.provider.request({method: 'personal_sign', params: circular}), e => e.code === -32602);
  assert.equal(f.posted.length, 0);
  assert.equal(f.globals.timers.size, 0);
});

test('provider keeps personal_sign and bounded Unicode usable', async () => {
  const f = pageFixture('provider');
  for (const params of [['0x00', ADDRESS], ['🔒'.repeat(45000)]]) {
    const pending = f.provider.request({method: 'personal_sign', params});
    const q = f.posted.at(-1);
    assert.equal(q.origin, ORIGIN);
    assert.equal(q.message.method, 'personal_sign');
    assert.deepEqual(plain(q.message.params), params);
    f.receive({id: q.message.id, result: 'fixture-response'});
    assert.equal(await pending, 'fixture-response');
  }
  assert.equal(f.globals.timers.size, 0);
});

test('content script independently enforces byte limits and ASCII public methods', () => {
  const f = pageFixture('content');
  let sequence = 0;
  for (const method of invalidMethods) {
    const id = `bad-method-${++sequence}`;
    f.receive({id, method, params: []});
    assert.equal(f.posted.at(-1).message.error.code, 4200, method);
  }
  for (const params of oversizedParams) {
    f.receive({id: `oversized-${++sequence}`, method: 'personal_sign', params});
    assert.equal(f.posted.at(-1).message.error.code, -32602);
  }
  const circular = []; circular.push(circular);
  f.receive({id: 'circular', method: 'personal_sign', params: circular});
  assert.equal(f.posted.at(-1).message.error.code, -32602);
  assert.equal(f.contentPort.sent.length, 0);
  f.receive({id: 'valid', method: 'personal_sign', params: ['🔒'.repeat(45000)]});
  assert.equal(f.contentPort.sent.length, 1);
  assert.equal(f.contentPort.sent[0].method, 'personal_sign');
});

test('content transport requires its own window and origin and discards page origin claims', () => {
  const f = pageFixture('content');
  const q = {id: 'one', method: 'personal_sign', params: ['0x00', ADDRESS], origin: OTHER};
  f.receive(q, {origin: OTHER});
  f.receive(q, {source: {iframe: true}});
  f.receive({...q, target: 'another-extension'});
  f.receive({...q, version: 2});
  assert.equal(f.contentPort.sent.length, 0);
  f.receive(q);
  assert.deepEqual(plain(f.contentPort.sent), [{id: 'one', method: 'personal_sign', params: q.params}]);
  f.receive({...q, params: ['replacement']});
  assert.equal(f.contentPort.sent.length, 1, 'duplicate page ID must not replace an in-flight request');
});

test('worker independently enforces UTF-8 bounds and public method syntax', async () => {
  const f = workerFixture(), p = f.connect();
  await settle();
  const before = f.nativeCalls.length;
  let sequence = 0;
  for (const method of invalidMethods) {
    p.onMessage.emit({id: `method-${++sequence}`, method, params: []});
    assert.equal(p.sent.at(-1).error.code, 4200, method);
  }
  for (const params of oversizedParams) {
    p.onMessage.emit({id: `oversized-${++sequence}`, method: 'personal_sign', params});
    assert.equal(p.sent.at(-1).error.code, -32602);
  }
  const circular = []; circular.push(circular);
  p.onMessage.emit({id: 'circular', method: 'personal_sign', params: circular});
  assert.equal(p.sent.at(-1).error.code, -32602);
  assert.equal(f.nativeCalls.length, before);
  p.onMessage.emit({id: 'valid', method: 'personal_sign', params: ['0x00', ADDRESS], origin: OTHER});
  await settle();
  const signing = f.nativeCalls.slice(before).filter(q => q.method === 'personal_sign');
  assert.equal(signing.length, 1);
  assert.equal(signing[0].origin, ORIGIN, 'page-supplied origin must not reach native host');
  assert.deepEqual(plain(signing[0].params), ['0x00', ADDRESS]);
});

test('worker refuses iframes, other extensions and inconsistent Chrome sender metadata', async () => {
  const f = workerFixture();
  for (const override of [
    {frameId: 1}, {frameId: undefined}, {id: 'other-extension'}, {tab: undefined},
    {tab: {id: 7}}, {tab: {id: 7, url: OTHER}}, {url: OTHER}, {url: undefined},
    {origin: OTHER}, {origin: undefined}, {origin: 'null'},
    {tab: {id: 7, url: 'not a URL'}},
  ]) {
    assert.equal(f.connect(7, ORIGIN, override).disconnected, true, JSON.stringify(override));
  }
  await settle();
  assert.equal(f.nativeCalls.length, 0);
  assert((await f.popup()).error, 'rejected senders must not populate the popup origin fallback');
});

test('worker keeps cancellation and native request IDs isolated between content ports', async () => {
  const f = workerFixture({id: 7}, {hold: ['eth_requestAccounts']});
  const a = f.connect(7, ORIGIN), b = f.connect(8, OTHER);
  await settle();
  a.onMessage.emit({id: 'same-page-id', method: 'eth_requestAccounts', params: []});
  b.onMessage.emit({id: 'same-page-id', method: 'eth_requestAccounts', params: []});
  const requests = f.nativeCalls.filter(q => q.method === 'eth_requestAccounts');
  assert.equal(requests.length, 2);
  assert.notEqual(requests[0].id, requests[1].id);
  b.onMessage.emit({cancel: requests[0].id});
  assert.equal(f.nativeCalls.filter(q => q.cancel).length, 0, 'native ID is not a page cancellation capability');
  b.onMessage.emit({cancel: 'same-page-id'});
  await settle();
  assert.deepEqual(f.nativeCalls.filter(q => q.cancel).map(q => q.cancel), [requests[1].id]);
  a.disconnect(); b.disconnect();
  await settle();
  assert.deepEqual(f.nativeCalls.filter(q => q.cancel).map(q => q.cancel), [requests[1].id, requests[0].id]);
});

const popupCases = [
  {name: 'missing URL uses authenticated origin', tab: {id: 7}, sites: [[7, ORIGIN]], expected: ORIGIN},
  {name: 'matching URL confirms origin', tab: {id: 7, url: `${ORIGIN}/path`}, sites: [[7, ORIGIN]], expected: ORIGIN},
  {name: 'same-origin ports remain unambiguous', tab: {id: 7}, sites: [[7, ORIGIN], [7, ORIGIN]], expected: ORIGIN},
  {name: 'no content script', tab: {id: 7}, sites: []},
  {name: 'content script in another tab', tab: {id: 7}, sites: [[8, ORIGIN]]},
  {name: 'conflicting navigation origins', tab: {id: 7}, sites: [[7, ORIGIN], [7, OTHER]]},
  {name: 'visible URL differs from stale content origin', tab: {id: 7, url: OTHER}, sites: [[7, ORIGIN]]},
  {name: 'opaque URL', tab: {id: 7, url: 'about:blank'}, sites: [[7, ORIGIN]]},
  {name: 'invalid URL', tab: {id: 7, url: 'not a URL'}, sites: [[7, ORIGIN]]},
  {name: 'missing tab ID', tab: {url: ORIGIN}, sites: [[7, ORIGIN]]},
  {name: 'no active tab', tab: null, sites: [[7, ORIGIN]]},
];

for (const c of popupCases) {
  test(`popup origin fallback: ${c.name}`, async () => {
    const f = workerFixture(c.tab);
    for (const site of c.sites) f.connect(...site);
    await settle();
    const before = f.nativeCalls.length;
    const response = await f.popup('status', {origin: 'https://attacker.example', tabId: 99});
    await settle();
    if (c.expected) {
      assert.equal(response.origin, c.expected);
      assert(f.nativeCalls.slice(before).every(q => q.origin === c.expected));
    } else {
      assert(response.error);
      assert.equal(f.nativeCalls.length, before, 'ambiguous or absent site must not reach the native host');
    }
  });
}

test('popup identity change uses Chrome tab origin, never message-supplied identity or origin', async () => {
  const f = workerFixture(), p = f.connect();
  await settle();
  const response = await f.popup('change', {origin: OTHER, identity: 'untrusted-identity', tabId: 99});
  await settle();
  assert.equal(response.origin, ORIGIN);
  const changes = f.nativeCalls.filter(q => q.method === '_changeIdentity');
  assert.equal(changes.length, 1);
  assert.equal(changes[0].origin, ORIGIN);
  assert.deepEqual(plain(changes[0].params), []);
  assert.equal(response.state.vaultURL, 'https://private-vault.example/app/');
  for (const message of p.sent.filter(m => m.event === 'state')) {
    assert.deepEqual(Object.keys(message.state).sort(), ['accounts', 'available', 'chainId']);
  }
});

test('only the real extension popup may request popup status or identity changes', async () => {
  const f = workerFixture(); f.connect();
  await settle();
  const before = f.nativeCalls.length;
  for (const sender of [
    {id: 'other-extension', url: POPUP},
    {id: 'fixture-extension', url: ORIGIN},
    {id: 'fixture-extension', url: `${POPUP}?spoof=1`},
    {id: 'fixture-extension', url: POPUP, tab: {id: 7}},
    {id: 'fixture-extension'},
  ]) {
    assert.equal((await f.popup('change', {}, sender)).ignored, true);
  }
  assert.equal((await f.popup('unsupported-action')).ignored, true);
  assert.equal(f.nativeCalls.length, before);
});

test('disconnected content port cannot provide a stale popup origin', async () => {
  const f = workerFixture(), p = f.connect();
  await settle();
  p.disconnect();
  await settle();
  const before = f.nativeCalls.length;
  assert((await f.popup()).error);
  assert.equal(f.nativeCalls.length, before);
});
