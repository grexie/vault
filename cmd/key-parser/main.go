//go:build js && wasm

package main

import (
	"github.com/grexie/remote-ssh-agent/internal/keyparse"
	"golang.org/x/crypto/ssh"
	"syscall/js"
)

func main() {
	js.Global().Set("parseSSHKey", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return map[string]any{"error": "Select a private key file"}
		}
		data := []byte(args[0].String())
		pass := []byte(args[1].String())
		defer clear(data)
		defer clear(pass)
		key, err := keyparse.Parse(data, pass)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		compact, err := keyparse.Compact(data, pass)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return map[string]any{"fingerprint": ssh.FingerprintSHA256(key.PublicKey()), "type": key.PublicKey().Type(), "compact": compact}
	}))
	js.Global().Call("postMessage", map[string]any{"ready": true})
	select {}
}
