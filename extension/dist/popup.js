// extension/src/popup.ts
var changing = false;
var $ = (id) => document.getElementById(id);
async function refresh(action = "status") {
  $("retry").setAttribute("disabled", "");
  try {
    const result = await chrome.runtime.sendMessage({ action });
    if (result?.error || !result?.state) throw new Error();
    const s = result.state;
    if (typeof s.vaultURL === "string") {
      const u = new URL(s.vaultURL);
      if (u.protocol === "https:" || u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) $("open-vault").setAttribute("href", u.href);
    }
    $("status").textContent = result.pending ? "Approval requested" : s.connected ? "Connected" : "Vault ready";
    $("status").classList.add("ready");
    $("detail").textContent = result.pending ? `${result.origin}
${result.pending.method}
Waiting for approval in Vault\u2026` : s.connected ? `${s.permission.identity}
${s.permission.address.slice(0, 8)}\u2026${s.permission.address.slice(-6)}` : "Connect this wallet from a Web3 website.";
    $("network").textContent = `${s.chain.chainName} \xB7 ${s.chain.chainId}`;
    $("website").textContent = result.origin;
    $("change").hidden = !s.connected;
    $("retry").hidden = true;
  } catch {
    $("status").textContent = "Vault unavailable";
    $("status").classList.remove("ready");
    $("detail").textContent = "Install the local integration with vault browser-wallet install, then try again.";
    $("network").textContent = "";
    $("website").textContent = "";
    $("change").hidden = true;
    $("retry").hidden = false;
  } finally {
    $("retry").removeAttribute("disabled");
  }
}
$("retry").addEventListener("click", () => void refresh("retry"));
$("change").addEventListener("click", async () => {
  if (changing) return;
  changing = true;
  $("change").setAttribute("disabled", "");
  $("status").textContent = "Approval requested";
  $("detail").textContent = "Choose another identity in Vault. Waiting for approval\u2026";
  try {
    await refresh("change");
  } finally {
    changing = false;
    $("change").removeAttribute("disabled");
  }
});
void refresh();
setInterval(() => {
  if (!changing) void refresh();
}, 8e3);
