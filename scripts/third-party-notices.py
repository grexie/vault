#!/usr/bin/env python3
"""Regenerate notices for Go modules imported by native and browser binaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'third_party' / 'licenses'
PREFIXES = ('license', 'licence', 'copying', 'notice', 'copyright')


def objects(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        yield value
        raw = raw[end:]


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True)


modules = {}
for env, packages in [
    (os.environ.copy(), ['./cmd/vault', './cmd/remote-ssh-agent']),
    ({**os.environ, 'GOOS': 'linux', 'GOARCH': 'arm64', 'CGO_ENABLED': '0'}, ['./cmd/vault']),
    ({**os.environ, 'GOOS': 'js', 'GOARCH': 'wasm'}, ['./cmd/vault-worker', './cmd/key-parser']),
]:
    for package in objects(run('go', 'list', '-deps', '-json', *packages, env=env)):
        module = package.get('Module', {})
        if module.get('Dir') and not module.get('Main'):
            modules[module['Path']] = module

rows = []
for name, module in sorted(modules.items()):
    source = Path(module['Dir'])
    target = OUT / (name + '@' + module['Version'])
    files = sorted(f for f in source.rglob('*') if f.is_file()
                   and f.name.lower().startswith(PREFIXES)
                   and f.suffix.lower() not in ('.go', '.json', '.toml', '.c', '.h'))
    if not files:
        raise SystemExit('No license notice found for ' + name)
    links = []
    for file in files:
        relative = file.relative_to(source)
        dest = target / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, dest)
        links.append(f'[{relative.as_posix()}]({dest.relative_to(ROOT).as_posix()})')
    rows.append(f"| `{name}` | `{module['Version']}` | {', '.join(links)} |")

sdk = Path(run('go', 'env', 'GOROOT').strip())
(OUT / 'go').mkdir(parents=True, exist_ok=True)
shutil.copyfile(sdk / 'LICENSE', OUT / 'go' / 'LICENSE')
notice = '''# Third-party notices

Grexie Vault's own source is released under the [MIT license](LICENSE). Dependencies retain their original licenses; the MIT license does not replace them. This list covers modules imported by the native binaries and browser WebAssembly, including module notices for bundled components. The Go standard library and WebAssembly runtime use the [Go license](third_party/licenses/go/LICENSE).

## Rebuilding and modifying components

The go-ethereum library is licensed under LGPL-3.0 (with individual files and bundled components retaining their stated licenses). Both the LGPL and GPL texts are included below. Vault does not restrict reverse engineering needed to debug modifications to those components. The full application build sources, pinned dependency versions and checksums, and scripts are public. Releases include a corresponding-source archive with vendored Go dependencies alongside the binaries so the combined application and browser worker can be rebuilt with a modified library.

Use Go 1.26.8 and Node.js 22+, unpack the source archive, run `npm ci`, then `GOFLAGS=-mod=vendor make build VERSION=local`. Native macOS Keychain support additionally uses the system Apple Security framework and a C toolchain. Rebuilding `make assets` regenerates the browser WebAssembly; `go build ./cmd/vault` embeds those assets into the server. Upstream module sources are also available using `go mod download` with the pinned `go.mod` and `go.sum` files.

Regenerate this inventory with `python3 scripts/third-party-notices.py` after changing dependencies. A license file in this inventory may cover other packages in that module that are not linked by Vault.

| Module | Version | License and notice files |
| --- | --- | --- |
'''
(ROOT / 'THIRD_PARTY_NOTICES.md').write_text(notice + '\n'.join(rows) + '''

## Chrome extension and test tooling

The extension runtime is original MIT-licensed TypeScript with no bundled third-party JavaScript runtime. Its esbuild/TypeScript build and Playwright/Anvil/Solidity/Ethers test dependencies are pinned in package-lock.json; npm publishes their original licenses. Independent signature fixtures include their exact upstream license and generation dependencies in [walletsign testdata](internal/walletsign/testdata/README.md) and [Hyperliquid testdata](internal/hyperliquid/testdata/README.md). Go MsgPack notices above apply to the Hyperliquid signing implementation.
''')
print(f'Wrote notices for {len(modules)} modules plus the Go runtime.')
