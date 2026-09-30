.PHONY: build assets test check clean
VERSION ?= dev
SKIP_EXTENSION_BUILD ?= 0

build: assets
	mkdir -p bin
	go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/remote-ssh-agent ./cmd/remote-ssh-agent
	go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/vault ./cmd/vault

assets:
	GOOS=js GOARCH=wasm go build -buildvcs=false -trimpath -ldflags '-s -w' -o web/static/key-parser.wasm ./cmd/key-parser
	GOOS=js GOARCH=wasm go build -buildvcs=false -trimpath -ldflags '-s -w' -o web/vault/vault-worker.wasm ./cmd/vault-worker
	install -m 0644 "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
	go run cmd/assets/main.go
ifeq ($(SKIP_EXTENSION_BUILD),0)
	node scripts/build-wallet-extension.mjs
endif

test: build
	go test -race ./...
	node --test web/crypto.test.js web/vault/sw.test.js web/vault/identity-names.test.js web/vault/request-time.test.js scripts/wallet-provider.test.mjs scripts/wallet-transport.test.mjs

check:
	node_modules/.bin/tsc -p extension/tsconfig.json
	go vet ./...
	node --check web/static/app.js
	node --check web/static/crypto.js
	node --check web/vault/app.js
	node --check web/vault/crypto.js
	node --check web/vault/sourcify.js
	node --check web/vault/sw.js
	node --check web/vault/identity-names.js

clean:
	rm -rf bin
