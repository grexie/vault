.PHONY: build assets test check clean
VERSION ?= dev

build: assets
	mkdir -p bin
	go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o bin/remote-ssh-agent ./cmd/remote-ssh-agent

assets:
	GOOS=js GOARCH=wasm go build -buildvcs=false -trimpath -ldflags '-s -w' -o web/static/key-parser.wasm ./cmd/key-parser
	install -m 0644 "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/static/wasm_exec.js
	go run cmd/assets/main.go

test: build
	go test -race ./...
	node --test web/crypto.test.js

check:
	go vet ./...
	node --check web/static/app.js
	node --check web/static/crypto.js

clean:
	rm -rf bin
