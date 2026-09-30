importScripts("/wasm_exec.js");
const go = new Go();
const ready = WebAssembly.instantiateStreaming(fetch("/vault-worker.wasm"), go.importObject).then(({instance}) => {go.run(instance);});
onmessage = async ({data}) => {
  try {await ready;const response = JSON.parse(vaultOperation(JSON.stringify(data.input)));postMessage({id: data.id, ...response});}
  catch (error) {postMessage({id: data.id, error: error.message || "Browser operation failed"});}
};
