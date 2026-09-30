// Direct browser lookup. No cookie, API key, private key or transaction body is
// sent to Sourcify; the URL contains only the public chain and contract address.
const root = "https://sourcify.dev/server/v2/contract";
const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const verified = (v) => v === "exact_match" || v === "match";

async function readLimited(response, max = 2 * 1024 * 1024) {
  if (!response.ok) throw new Error(response.status === 404 ? "No verified ABI found" : "ABI lookup is unavailable");
  const reader = response.body.getReader();
  const chunks = []; let size = 0;
  try {
    for (;;) {
      const {value, done} = await reader.read(); if (done) break;
      size += value.length; if (size > max) throw new Error("Contract ABI exceeds the size limit");
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) {bytes.set(chunk, offset); offset += chunk.length;}
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function verifiedABIs(chainId, address, {fetcher = fetch, signal} = {}) {
  const chain = BigInt(chainId).toString();
  if (!/^[1-9][0-9]{0,19}$/.test(chain) || !addressPattern.test(address)) throw new Error("Invalid contract or network");
  const visited = new Set(); const contracts = []; const warnings = [];
  async function lookup(addr, depth) {
    const lower = addr.toLowerCase();
    if (visited.has(lower)) return;
    if (depth > 3 || visited.size >= 8) throw new Error("Proxy resolution exceeds the safety limit");
    visited.add(lower);
    const url = `${root}/${chain}/${lower}?fields=abi,compilation.name,proxyResolution`;
    const data = await readLimited(await fetcher(url, {
      credentials: "omit", referrerPolicy: "no-referrer", redirect: "error", cache: "no-store",
      signal: signal || AbortSignal.timeout(12000), headers: {Accept: "application/json"},
    }));
    if (String(data.chainId) !== chain || data.address?.toLowerCase() !== lower || !verified(data.runtimeMatch) || !Array.isArray(data.abi)) throw new Error("No verified runtime ABI for this contract");
    contracts.push({address: lower, abi: data.abi, name: String(data.compilation?.name || ""), match: data.runtimeMatch,
      source: `https://repo.sourcify.dev/${chain}/${lower}`, implementation: depth > 0});
    const proxy = data.proxyResolution;
    if (!proxy || proxy.proxyResolutionError || typeof proxy.isProxy !== "boolean") {
      warnings.push("Proxy detection was unavailable. The implementation ABI may be missing."); return;
    }
    if (proxy.isProxy) {
      warnings.push("This is an upgradeable or delegated contract. Its implementation can change before the transaction executes.");
      if (!Array.isArray(proxy.implementations) || !proxy.implementations.length) {warnings.push("No verified proxy implementation could be resolved."); return;}
      for (const implementation of proxy.implementations) {
        if (!addressPattern.test(implementation.address)) throw new Error("Invalid proxy implementation address");
        try {await lookup(implementation.address, depth + 1);} catch {warnings.push("A proxy implementation has no usable verified ABI.");}
      }
    }
  }
  await lookup(address, 0);
  return {contracts, warnings: [...new Set(warnings)], fetchedAt: new Date().toISOString()};
}

// A download is a plain JSON ABI. The filename comes from validated public
// identifiers, never from a remote contract name or source-provided path.
export function downloadABI(chainId, contract) {
  const chain = BigInt(chainId).toString();
  if (!addressPattern.test(contract.address) || !Array.isArray(contract.abi)) throw new Error("Invalid ABI");
  const blob = new Blob([JSON.stringify(contract.abi, null, 2)], {type: "application/json"});
  const href = URL.createObjectURL(blob); const a = document.createElement("a");
  a.href = href; a.download = `abi-${chain}-${contract.address.toLowerCase()}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
