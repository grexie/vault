#!/usr/bin/env node
// Offline reference fixtures only. The hard-coded key below is PUBLIC TEST DATA.
// Run with Node 22/24 and an isolated npm-ci runtime; see testdata/README.md.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';

const args = process.argv.slice(2);
if (args.length < 1 || args.length > 2 || (args[1] && args[1] !== '--write')) {
  throw new Error('Usage: node scripts/test-wallet-signatures.mjs RUNTIME_DIR [--write]');
}
const runtime = path.resolve(args[0]);
const outputDir = fileURLToPath(new URL('../internal/walletsign/testdata/', import.meta.url));
const denied = () => { throw new Error('Network is disabled in wallet fixture generation'); };
globalThis.fetch = denied;
net.Socket.prototype.connect = denied;
net.connect = net.createConnection = tls.connect = denied;
http.request = http.get = https.request = https.get = denied;
for (const key of ['lookup', 'resolve', 'resolve4', 'resolve6', 'reverse']) {
  dns[key] = denied;
  dns.promises[key] = denied;
}
assert.throws(() => net.createConnection({ host: 'example.invalid', port: 443 }), /Network is disabled/);
assert.throws(() => dns.lookup('example.invalid'), /Network is disabled/);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const filesSha256 = {
  'package.json': '7169f2a9baae6bd6c78850d26ce0caa589fe8052ba8bd9447be01b8190aa9424',
  LICENSE: '31ece466097a09d5226c3bbb06543d8f7b6881de291f5f0d4142daaadb30e324',
  'dist/sign-typed-data.js': 'b885497768eee87c6d2f137c901d8a94748c7d272d9b444ea4e6ddb83f6e972e',
  'dist/personal-sign.js': 'f07f6247932a516553cd03d4bc8a9c33a43321dd0a7b9c979127ea4848405463',
  'dist/utils.js': 'c997706cd7328896f1e78ddf5a2138c693ad24cefc502e31550154f2542b4fa2',
};
for (const [file, hash] of Object.entries(filesSha256)) {
  assert.equal(sha256(fs.readFileSync(path.join(runtime, 'node_modules/@metamask/eth-sig-util', file))), hash, file);
}
const lockHash = '0307801a033e5070f57fb54316842a4511cc75e69568492ace0ab8e4af1d2441';
assert.equal(sha256(fs.readFileSync(path.join(runtime, 'package-lock.json'))), lockHash, 'pinned dependency lock');
assert.equal(sha256(fs.readFileSync(path.join(outputDir, 'package-lock.json'))), lockHash, 'checked-in dependency lock');
const require = createRequire(path.join(runtime, 'package.json'));
const sigUtil = require('@metamask/eth-sig-util');
const ethUtil = require('@ethereumjs/util');
const { keccak256 } = require('ethereum-cryptography/keccak');
assert.equal(JSON.parse(fs.readFileSync(path.join(runtime, 'node_modules/@metamask/eth-sig-util/package.json'), 'utf8')).version, '9.0.0');

// This public disposable key is also in the official Hyperliquid SDK tests.
// Never fund it, substitute a production key, or accept a key through arguments.
const testPrivateKey = '0x0123456789012345678901234567890123456789012345678901234567890123';
const privateKey = Buffer.from(testPrivateKey.slice(2), 'hex');
const hex = (value) => `0x${Buffer.from(value).toString('hex')}`;
const signerAddress = hex(ethUtil.privateToAddress(privateKey));
const copy = (value) => JSON.parse(JSON.stringify(value));
const vectors = [], rejections = [], compatibilityCases = [];
const address = '0x1111111111111111111111111111111111111111';
const domainTypes = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }, { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
const defaultDomain = { name: 'Vault offline test', version: '1', chainId: 1, verifyingContract: address };
function typed(fields, message, extra = {}) {
  return { types: { EIP712Domain: copy(domainTypes), Test: fields }, primaryType: 'Test', domain: copy(defaultDomain), message, ...extra };
}
function test(name, method, data, version, category = 'valid', note = '') {
  data = copy(data);
  const row = { name, method, ...(version ? { version } : {}), input: { data } };
  row.rpcParams = method === 'personal_sign' ? [data, signerAddress]
    : method === 'eth_sign' ? [signerAddress, data]
      : version === 'V1' ? [data, signerAddress] : [signerAddress, JSON.stringify(data)];
  if (note) row.note = note;
  try {
    if (method === 'personal_sign' || method === 'eth_sign') {
      assert.match(data, /^0x(?:[0-9a-fA-F]{2})*$/, 'fixture message must be exact bytes');
      const bytes = Buffer.from(data.slice(2), 'hex');
      const preimage = Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${bytes.length}`, 'utf8'), bytes]);
      row.messageLength = bytes.length;
      row.preimage = hex(preimage);
      row.digest = hex(keccak256(preimage));
      assert.equal(row.digest, hex(ethUtil.hashPersonalMessage(bytes)));
      row.signature = sigUtil.personalSign({ privateKey, data });
      row.recoveredAddress = sigUtil.recoverPersonalSignature({ data, signature: row.signature });
    } else {
      row.digest = version === 'V1' ? sigUtil.typedSignatureHash(data) : hex(sigUtil.TypedDataUtils.eip712Hash(data, version));
      if (version !== 'V1') {
        row.domainHash = hex(sigUtil.TypedDataUtils.eip712DomainHash(data, version));
        if (data.primaryType !== 'EIP712Domain') row.messageHash = hex(sigUtil.TypedDataUtils.hashStruct(data.primaryType, data.message, data.types, version));
      }
      row.signature = sigUtil.signTypedData({ privateKey, data, version });
      row.recoveredAddress = sigUtil.recoverTypedSignature({ data, signature: row.signature, version });
    }
    assert.equal(row.recoveredAddress, signerAddress, name);
    // Verify the serialized signature independently of the typed-data recovery API.
    const signature = ethUtil.fromRpcSig(row.signature);
    assert.equal(hex(ethUtil.pubToAddress(ethUtil.ecrecover(Buffer.from(row.digest.slice(2), 'hex'), signature.v, signature.r, signature.s))), signerAddress);
    if (category === 'reject') throw new Error(`Expected reference rejection: ${name}`);
    if (category === 'compatibility') {
      row.recommendation = 'reject';
      compatibilityCases.push(row);
    } else vectors.push(row);
  } catch (error) {
    if (category !== 'reject') throw error;
    assert(!String(error.message).startsWith('Expected reference rejection:'), error.message);
    row.expectedError = String(error.message);
    rejections.push(row);
  }
}
function typedBoth(name, data, category = 'valid', note = '') {
  for (const version of ['V3', 'V4']) test(`${version.toLowerCase()}/${name}`, `eth_signTypedData_${version.toLowerCase()}`, data, version, category, note);
}

const messages = {
  empty: Buffer.alloc(0), ascii: Buffer.from('Vault offline signature test'),
  unicode: Buffer.from('Vault 🔐 café — 你好', 'utf8'), nul: Buffer.from([0, 65, 0, 255]),
  '32-bytes': Buffer.from('11'.repeat(32), 'hex'), 'all-bytes': Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
  'prefix-looking': Buffer.from('\x19Ethereum Signed Message:\n5hello'),
};
for (const [name, message] of Object.entries(messages)) {
  for (const method of ['personal_sign', 'eth_sign']) test(`${method}/${name}`, method, hex(message));
}

const v1 = [
  ['basic', [{ name: 'Message', type: 'string', value: 'Vault offline test' }, { name: 'A number', type: 'uint32', value: 1337 }]],
  ['integers', [{ name: 'maximum', type: 'uint256', value: (2n ** 256n - 1n).toString() }, { name: 'minimum', type: 'int256', value: (-(2n ** 255n)).toString() }]],
  ['bytes-address-bools', [{ name: 'recipient', type: 'address', value: address }, { name: 'payload', type: 'bytes', value: '0x001122ff' }, { name: 'tag', type: 'bytes4', value: '0x11223344' }, { name: 'enabled', type: 'bool', value: false }]],
  ['integer-array', [{ name: 'amounts', type: 'uint256[]', value: ['0', '9007199254740993', '0xffff'] }]],
  ['address-array', [{ name: 'owners', type: 'address[]', value: [address, signerAddress] }]],
  ['signed-array', [{ name: 'deltas', type: 'int8[]', value: [-128, -1, 0, 127] }]],
  ['unicode', [{ name: 'message', type: 'string', value: '🔐 café 你好' }]],
];
for (const [name, data] of v1) test(`v1/${name}`, 'eth_signTypedData', data, 'V1');
test('v1/explicit-alias', 'eth_signTypedData_v1', v1[0][1], 'V1');
test('v1/empty', 'eth_signTypedData', [], 'V1', 'reject');
test('v1/missing-name', 'eth_signTypedData', [{ type: 'string', value: 'test' }], 'V1', 'reject');
test('v1/function', 'eth_signTypedData', [{ name: 'f', type: 'function', value: '0x' + '11'.repeat(24) }], 'V1', 'reject');
for (const values of [['a', 'bc'], ['ab', 'c']]) {
  test(`v1/packed-string-collision-${values.join('-')}`, 'eth_signTypedData', values.map((value, i) => ({ name: `field${i}`, type: 'string', value })), 'V1', 'compatibility', 'Legacy packed dynamic values collide. These distinct inputs have the same digest; do not present V1 as strongly structured authorization.');
}

const mail = {
  types: {
    EIP712Domain: copy(domainTypes),
    Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }],
    Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }],
  },
  primaryType: 'Mail', domain: { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' },
  message: { from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' }, to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' }, contents: 'Hello, Bob!' },
};
typedBoth('eip712-mail', mail);
typedBoth('uint-limits', typed([{ name: 'small', type: 'uint8' }, { name: 'large', type: 'uint256' }, { name: 'hex', type: 'uint256' }], { small: 255, large: (2n ** 256n - 1n).toString(), hex: '0x20000000000001' }));
typedBoth('signed-limits', typed([{ name: 'min', type: 'int256' }, { name: 'max', type: 'int8' }], { min: (-(2n ** 255n)).toString(), max: 127 }));
typedBoth('bytes-string-bool', typed([{ name: 'raw', type: 'bytes' }, { name: 'fixed', type: 'bytes4' }, { name: 'message', type: 'string' }, { name: 'enabled', type: 'bool' }], { raw: '0x0001ff', fixed: '0x11223344', message: 'Vault 🔐 café 你好', enabled: false }));
typedBoth('empty-domain', typed([{ name: 'value', type: 'uint256' }], { value: '42' }, { types: { EIP712Domain: [], Test: [{ name: 'value', type: 'uint256' }] }, domain: {} }));
for (const chainId of [0, '0x1', '9007199254740993']) typedBoth(`domain-chain-${chainId}`, typed([{ name: 'value', type: 'uint256' }], { value: '42' }, { domain: { ...defaultDomain, chainId } }));
typedBoth('salt-domain', { types: { EIP712Domain: [{ name: 'salt', type: 'bytes32' }], Test: [{ name: 'value', type: 'uint256' }] }, domain: { salt: '0x' + '55'.repeat(32) }, primaryType: 'Test', message: { value: 1 } });
typedBoth('domain-only', { types: { EIP712Domain: copy(domainTypes) }, primaryType: 'EIP712Domain', domain: copy(defaultDomain), message: {} });
typedBoth('domain-only-unsigned-message', { types: { EIP712Domain: copy(domainTypes) }, primaryType: 'EIP712Domain', domain: copy(defaultDomain), message: { name: 'This claim is not signed', chainId: 999 } }, 'compatibility', 'When primaryType is EIP712Domain the entire message object is ignored, even fields matching the domain schema. Omit it from signed review and label it unsigned.');
typedBoth('unsigned-domain-chain-id', typed([{ name: 'value', type: 'uint256' }], { value: 42 }, { types: { EIP712Domain: [], Test: [{ name: 'value', type: 'uint256' }] }, domain: { chainId: 1 } }), 'compatibility', 'An undeclared domain.chainId is not hashed. Do not display it as a signed domain or suppress the missing chain-binding warning.');
// Public application call shapes, synthetic historical timestamp and addresses.
// The real app adds two fields not present in the signed EIP-712 struct.
for (const [network, chainId] of [['Mainnet', 42161], ['Testnet', 421614]]) {
  for (const [action, primaryType, fields, message] of [
    ['acceptTerms', 'Hyperliquid:AcceptTerms', [{ name: 'hyperliquidChain', type: 'string' }, { name: 'time', type: 'uint64' }], { hyperliquidChain: network, time: 1700000000123 }],
    ['approveAgent', 'HyperliquidTransaction:ApproveAgent', [{ name: 'hyperliquidChain', type: 'string' }, { name: 'agentAddress', type: 'address' }, { name: 'agentName', type: 'string' }, { name: 'nonce', type: 'uint64' }], { hyperliquidChain: network, agentAddress: address, agentName: 'Offline test only', nonce: 1700000000123 }],
  ]) {
    const data = { types: { EIP712Domain: copy(domainTypes), [primaryType]: fields }, primaryType, domain: { name: 'HyperliquidSignTransaction', version: '1', chainId, verifyingContract: '0x' + '00'.repeat(20) }, message };
    test(`v4/hyperliquid-${network.toLowerCase()}-${action}-signed-fields`, 'eth_signTypedData_v4', data, 'V4');
    const raw = copy(data); raw.message.type = action; raw.message.signatureChainId = `0x${chainId.toString(16)}`;
    test(`v4/hyperliquid-${network.toLowerCase()}-${action}-raw-app`, 'eth_signTypedData_v4', raw, 'V4', 'compatibility', 'The public app preserves unsigned type/signatureChainId fields. Either reject, or canonicalize only declared fields and explicitly warn about excluded metadata. These extras must not appear as authenticated fields.');
  }
}
const arrayCases = [
  ['uint-array', typed([{ name: 'values', type: 'uint256[]' }], { values: [0, '9007199254740993', '0xffff'] })],
  ['empty-array', typed([{ name: 'values', type: 'uint256[]' }], { values: [] })],
  ['fixed-array', typed([{ name: 'values', type: 'uint256[2]' }], { values: [1, 2] })],
  ['nested-array', typed([{ name: 'values', type: 'uint256[][]' }], { values: [[1, 2], [], ['9007199254740993']] })],
  ['struct-array', { ...mail, types: { ...mail.types, Group: [{ name: 'members', type: 'Person[]' }] }, primaryType: 'Group', message: { members: [mail.message.from, mail.message.to] } }],
  ['string-array', typed([{ name: 'values', type: 'string[]' }], { values: ['a', 'bc', '', '🔐'] })],
];
for (const [name, data] of arrayCases) {
  test(`v3/${name}`, 'eth_signTypedData_v3', data, 'V3', 'reject');
  test(`v4/${name}`, 'eth_signTypedData_v4', data, 'V4');
}
const recursive = { types: { EIP712Domain: [], Node: [{ name: 'value', type: 'uint256' }, { name: 'next', type: 'Node' }] }, primaryType: 'Node', domain: {}, message: { value: 1, next: { value: 2, next: null } } };
test('v4/recursive-terminated', 'eth_signTypedData_v4', recursive, 'V4');
test('v3/recursive-null', 'eth_signTypedData_v3', recursive, 'V3', 'reject');

for (const [name, fieldType] of [['primitive', 'uint256'], ['array', 'uint256[]']]) {
  const data = typed([{ name: 'omitted', type: fieldType }], {});
  test(`v3/missing-${name}`, 'eth_signTypedData_v3', data, 'V3', 'compatibility', 'V3 silently skips absent fields, including an absent array. Reject rather than show unsigned placeholders.');
  test(`v4/missing-${name}`, 'eth_signTypedData_v4', data, 'V4', 'reject');
}
for (const value of [undefined, null]) {
  const data = copy(mail); if (value === undefined) delete data.message.from; else data.message.from = value;
  test(`v4/${value === null ? 'null' : 'missing'}-struct`, 'eth_signTypedData_v4', data, 'V4', 'compatibility', 'V4 hashes a nullish struct as zero bytes32; reject unless approval explicitly identifies the omitted struct.');
}
const nullStruct = copy(mail); nullStruct.message.from = null;
test('v3/null-struct', 'eth_signTypedData_v3', nullStruct, 'V3', 'reject');
const extraField = copy(mail); extraField.message.transferEverything = true;
typedBoth('ignored-extra-message-field', extraField, 'compatibility', 'Undeclared object fields are ignored by the hash. Reject; the approval must never imply these fields were authorized.');
const extraDomain = copy(mail); extraDomain.domain.salt = '0x' + '55'.repeat(32);
typedBoth('ignored-extra-domain-field', extraDomain, 'compatibility', 'Undeclared domain fields are ignored by the hash. Reject to prevent a false impression of domain binding.');
const missingDomain = copy(mail); delete missingDomain.domain.chainId;
test('v3/missing-domain-chain-id', 'eth_signTypedData_v3', missingDomain, 'V3', 'compatibility', 'V3 silently omits a declared but absent domain field.');
test('v4/missing-domain-chain-id', 'eth_signTypedData_v4', missingDomain, 'V4', 'reject');
const wrongFixedLength = typed([{ name: 'values', type: 'uint256[2]' }], { values: [1] });
test('v4/wrong-fixed-array-length', 'eth_signTypedData_v4', wrongFixedLength, 'V4', 'compatibility', 'Reference hashes wrong-length fixed arrays without checking the declared length. Reject invalid cardinality.');
typedBoth('uint-overflow', typed([{ name: 'value', type: 'uint8' }], { value: 256 }), 'reject');
typedBoth('uint-negative', typed([{ name: 'value', type: 'uint256' }], { value: '-1' }), 'reject');
typedBoth('unsupported-function', typed([{ name: 'value', type: 'function' }], { value: '0x' + '11'.repeat(24) }), 'reject');
typedBoth('int8-noncanonical-positive', typed([{ name: 'value', type: 'int8' }], { value: 255 }), 'compatibility', 'Reference preserves historical intN range permissiveness. Reject values outside the signed integer range.');
for (const version of ['V1', 'V3', 'V4']) {
  for (const value of [true, false, 'true', 'false', 0, 1, '', '0', 'FALSE', 'arbitrary', null]) {
    const data = version === 'V1' ? [{ name: 'enabled', type: 'bool', value }] : typed([{ name: 'enabled', type: 'bool' }], { enabled: value });
    const category = typeof value === 'boolean' ? 'valid' : (value === 'true' || value === 'false') ? 'compatibility' : 'reject';
    test(`${version.toLowerCase()}/bool-${JSON.stringify(value)}`, version === 'V1' ? 'eth_signTypedData' : `eth_signTypedData_${version.toLowerCase()}`, data, version, category, category === 'compatibility' ? 'Reference normalizes exact boolean strings safely; Vault may reject non-boolean JSON for a smaller input language.' : '');
  }
}

assert.equal(compatibilityCases.find(v => v.name === 'v1/packed-string-collision-a-bc').digest, compatibilityCases.find(v => v.name === 'v1/packed-string-collision-ab-c').digest);
for (const method of ['personal_sign', 'eth_sign']) assert.equal(vectors.find(v => v.name === `${method}/empty`).digest, '0x5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad');
const result = {
  schemaVersion: 1,
  warning: 'PUBLIC DISPOSABLE TEST KEY. NEVER FUND. Offline compatibility fixtures are not authorizations. Compatibility cases deliberately document unsafe or ambiguous SDK acceptance; Vault should reject them.',
  reference: {
    package: '@metamask/eth-sig-util', version: '9.0.0',
    repository: 'https://github.com/MetaMask/eth-sig-util', gitCommit: '5a89b8ba61e7e7a9c55f5b1eac6cb236a2a1082d',
    tarball: 'https://registry.npmjs.org/@metamask/eth-sig-util/-/eth-sig-util-9.0.0.tgz',
    tarballSha256: 'edbdf9610830fd54d04468417ccfa1ba65b0bf3e57cca3712ddf93271af01216',
    integrity: 'sha512-iB/iNjA+f+Vl4RlxbWw96UJGJnGG5SP4kZjGlR+e8IC2bTRIzx46r9Xr5mpWgAGeU4G3o3KuXeWRLffhr+JtxA==',
    license: 'ISC', licenseFile: 'metamask-eth-sig-util-LICENSE.txt', filesSha256, dependencyLockSha256: lockHash,
    gethEthSign: 'https://github.com/ethereum/go-ethereum/blob/v1.17.6/internal/ethapi/api.go#L1867-L1890',
    ethSignSemantics: 'Geth eth_sign: keccak256(0x19 || UTF8("Ethereum Signed Message:\\n") || ASCII(decimal byte length) || message bytes). Same prefix/digest as personal_sign, not raw digest signing.',
  },
  testPrivateKey, signerAddress, vectors, rejections, compatibilityCases,
};
const output = `${JSON.stringify(result, null, 2)}\n`;
const outputPath = path.join(outputDir, 'metamask-vectors.json');
if (args[1] === '--write') fs.writeFileSync(outputPath, output);
else assert.equal(fs.readFileSync(outputPath, 'utf8'), output, 'checked-in vectors must regenerate exactly');
console.log(`${args[1] === '--write' ? 'Wrote' : 'Verified'} ${vectors.length} valid, ${rejections.length} rejected, ${compatibilityCases.length} compatibility-edge cases; all signatures recovered ${signerAddress}. Network disabled.`);
