/* Keys are parsed in a disposable worker, using the same Go parser as the signer. */
importScripts("/wasm_exec.js");
const go = new Go();
WebAssembly.instantiateStreaming(fetch("/key-parser.wasm"), go.importObject)
  .then((result) => go.run(result.instance))
  .catch(() =>
    postMessage({
      error: "Could not load the local key validator. Reload and try again.",
    }),
  );
self.onmessage = (event) => {
  try {
    postMessage(parseSSHKey(event.data.key, event.data.passphrase));
  } catch {
    postMessage({ error: "The key could not be parsed." });
  }
};
