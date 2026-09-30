# Third-party notices

Grexie Vault's own source is released under the [MIT license](LICENSE). Dependencies retain their original licenses; the MIT license does not replace them. This list covers modules imported by the native binaries and browser WebAssembly, including module notices for bundled components. The Go standard library and WebAssembly runtime use the [Go license](third_party/licenses/go/LICENSE).

## Rebuilding and modifying components

The go-ethereum library is licensed under LGPL-3.0 (with individual files and bundled components retaining their stated licenses). Both the LGPL and GPL texts are included below. Vault does not restrict reverse engineering needed to debug modifications to those components. The full application build sources, pinned dependency versions and checksums, and scripts are public. Releases include a corresponding-source archive with vendored Go dependencies alongside the binaries so the combined application and browser worker can be rebuilt with a modified library.

Use Go 1.26.8, unpack the source archive, then run `GOFLAGS=-mod=vendor make build VERSION=local`. Native macOS Keychain support additionally uses the system Apple Security framework and a C toolchain. Rebuilding `make assets` regenerates the browser WebAssembly; `go build ./cmd/vault` embeds those assets into the server. Upstream module sources are also available using `go mod download` with the pinned `go.mod` and `go.sum` files.

Regenerate this inventory with `python3 scripts/third-party-notices.py` after changing dependencies. A license file in this inventory may cover other packages in that module that are not linked by Vault.

| Module | Version | License and notice files |
| --- | --- | --- |
| `filippo.io/age` | `v1.3.2` | [.github/workflows/LICENSE.suffix.txt](third_party/licenses/filippo.io/age@v1.3.2/.github/workflows/LICENSE.suffix.txt), [LICENSE](third_party/licenses/filippo.io/age@v1.3.2/LICENSE) |
| `filippo.io/edwards25519` | `v1.2.0` | [LICENSE](third_party/licenses/filippo.io/edwards25519@v1.2.0/LICENSE) |
| `filippo.io/hpke` | `v0.4.0` | [LICENSE](third_party/licenses/filippo.io/hpke@v0.4.0/LICENSE) |
| `github.com/SherClockHolmes/webpush-go` | `v1.4.0` | [LICENSE](third_party/licenses/github.com/SherClockHolmes/webpush-go@v1.4.0/LICENSE) |
| `github.com/bits-and-blooms/bitset` | `v1.20.0` | [LICENSE](third_party/licenses/github.com/bits-and-blooms/bitset@v1.20.0/LICENSE) |
| `github.com/btcsuite/btcd` | `v0.24.2` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd@v0.24.2/LICENSE), [txscript/data/LICENSE](third_party/licenses/github.com/btcsuite/btcd@v0.24.2/txscript/data/LICENSE) |
| `github.com/btcsuite/btcd/btcec/v2` | `v2.5.0` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd/btcec/v2@v2.5.0/LICENSE) |
| `github.com/btcsuite/btcd/btcutil` | `v1.1.5` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd/btcutil@v1.1.5/LICENSE) |
| `github.com/btcsuite/btcd/btcutil/psbt` | `v1.2.0` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd/btcutil/psbt@v1.2.0/LICENSE) |
| `github.com/btcsuite/btcd/chaincfg/chainhash` | `v1.1.0` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd/chaincfg/chainhash@v1.1.0/LICENSE) |
| `github.com/btcsuite/btcd/chainhash/v2` | `v2.0.0` | [LICENSE](third_party/licenses/github.com/btcsuite/btcd/chainhash/v2@v2.0.0/LICENSE) |
| `github.com/btcsuite/btclog` | `v1.0.0` | [LICENSE](third_party/licenses/github.com/btcsuite/btclog@v1.0.0/LICENSE) |
| `github.com/consensys/gnark-crypto` | `v0.18.1` | [LICENSE](third_party/licenses/github.com/consensys/gnark-crypto@v0.18.1/LICENSE) |
| `github.com/crate-crypto/go-eth-kzg` | `v1.5.0` | [LICENSE](third_party/licenses/github.com/crate-crypto/go-eth-kzg@v1.5.0/LICENSE) |
| `github.com/cronokirby/saferith` | `v0.33.0` | [LICENSE](third_party/licenses/github.com/cronokirby/saferith@v0.33.0/LICENSE), [LICENSE_go](third_party/licenses/github.com/cronokirby/saferith@v0.33.0/LICENSE_go) |
| `github.com/decred/dcrd/crypto/blake256` | `v1.1.0` | [LICENSE](third_party/licenses/github.com/decred/dcrd/crypto/blake256@v1.1.0/LICENSE) |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | `v4.4.0` | [LICENSE](third_party/licenses/github.com/decred/dcrd/dcrec/secp256k1/v4@v4.4.0/LICENSE) |
| `github.com/ethereum/go-ethereum` | `v1.17.6` | [COPYING](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/COPYING), [COPYING.LESSER](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/COPYING.LESSER), [crypto/bn256/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/bn256/LICENSE), [crypto/bn256/cloudflare/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/bn256/cloudflare/LICENSE), [crypto/ecies/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/ecies/LICENSE), [crypto/keccak/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/keccak/LICENSE), [crypto/secp256k1/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/secp256k1/LICENSE), [crypto/secp256k1/libsecp256k1/COPYING](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/crypto/secp256k1/libsecp256k1/COPYING), [metrics/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/metrics/LICENSE), [metrics/influxdb/LICENSE](third_party/licenses/github.com/ethereum/go-ethereum@v1.17.6/metrics/influxdb/LICENSE) |
| `github.com/fxamacker/cbor/v2` | `v2.9.4` | [LICENSE](third_party/licenses/github.com/fxamacker/cbor/v2@v2.9.4/LICENSE) |
| `github.com/go-viper/mapstructure/v2` | `v2.5.0` | [LICENSE](third_party/licenses/github.com/go-viper/mapstructure/v2@v2.5.0/LICENSE) |
| `github.com/go-webauthn/webauthn` | `v0.18.2` | [LICENSE](third_party/licenses/github.com/go-webauthn/webauthn@v0.18.2/LICENSE) |
| `github.com/go-webauthn/x` | `v0.3.1` | [LICENSE](third_party/licenses/github.com/go-webauthn/x@v0.3.1/LICENSE), [crypto/blake256/LICENSE](third_party/licenses/github.com/go-webauthn/x@v0.3.1/crypto/blake256/LICENSE), [crypto/secp256k1/LICENSE](third_party/licenses/github.com/go-webauthn/x@v0.3.1/crypto/secp256k1/LICENSE), [revoke/LICENSE](third_party/licenses/github.com/go-webauthn/x@v0.3.1/revoke/LICENSE) |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | [LICENSE](third_party/licenses/github.com/golang-jwt/jwt/v5@v5.3.1/LICENSE) |
| `github.com/google/go-tpm` | `v0.9.8` | [LICENSE](third_party/licenses/github.com/google/go-tpm@v0.9.8/LICENSE) |
| `github.com/google/uuid` | `v1.6.0` | [LICENSE](third_party/licenses/github.com/google/uuid@v1.6.0/LICENSE) |
| `github.com/gorilla/websocket` | `v1.5.3` | [LICENSE](third_party/licenses/github.com/gorilla/websocket@v1.5.3/LICENSE) |
| `github.com/holiman/uint256` | `v1.3.2` | [COPYING](third_party/licenses/github.com/holiman/uint256@v1.3.2/COPYING) |
| `github.com/klauspost/compress` | `v1.19.2` | [LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/LICENSE), [gzhttp/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/gzhttp/LICENSE), [internal/lz4ref/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/internal/lz4ref/LICENSE), [internal/snapref/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/internal/snapref/LICENSE), [s2/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/s2/LICENSE), [s2/cmd/internal/filepathx/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/s2/cmd/internal/filepathx/LICENSE), [s2/cmd/internal/readahead/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/s2/cmd/internal/readahead/LICENSE), [snappy/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/snappy/LICENSE), [snappy/xerial/LICENSE](third_party/licenses/github.com/klauspost/compress@v1.19.2/snappy/xerial/LICENSE), [zstd/internal/xxhash/LICENSE.txt](third_party/licenses/github.com/klauspost/compress@v1.19.2/zstd/internal/xxhash/LICENSE.txt) |
| `github.com/klauspost/cpuid/v2` | `v2.2.5` | [LICENSE](third_party/licenses/github.com/klauspost/cpuid/v2@v2.2.5/LICENSE) |
| `github.com/philhofer/fwd` | `v1.2.0` | [LICENSE.md](third_party/licenses/github.com/philhofer/fwd@v1.2.0/LICENSE.md) |
| `github.com/taurusgroup/multi-party-sig` | `v0.7.0-alpha-2025-01-28` | [LICENCE](third_party/licenses/github.com/taurusgroup/multi-party-sig@v0.7.0-alpha-2025-01-28/LICENCE) |
| `github.com/tinylib/msgp` | `v1.6.4` | [LICENSE](third_party/licenses/github.com/tinylib/msgp@v1.6.4/LICENSE) |
| `github.com/x448/float16` | `v0.8.4` | [LICENSE](third_party/licenses/github.com/x448/float16@v0.8.4/LICENSE) |
| `github.com/xdg-go/scram` | `v1.2.0` | [LICENSE](third_party/licenses/github.com/xdg-go/scram@v1.2.0/LICENSE) |
| `github.com/xdg-go/stringprep` | `v1.0.4` | [LICENSE](third_party/licenses/github.com/xdg-go/stringprep@v1.0.4/LICENSE) |
| `github.com/youmark/pkcs8` | `v0.0.0-20240726163527-a2c0da244d78` | [LICENSE](third_party/licenses/github.com/youmark/pkcs8@v0.0.0-20240726163527-a2c0da244d78/LICENSE) |
| `github.com/zeebo/blake3` | `v0.2.3` | [LICENSE](third_party/licenses/github.com/zeebo/blake3@v0.2.3/LICENSE) |
| `go.etcd.io/bbolt` | `v1.5.0` | [LICENSE](third_party/licenses/go.etcd.io/bbolt@v1.5.0/LICENSE) |
| `go.mongodb.org/mongo-driver/v2` | `v2.9.1` | [LICENSE](third_party/licenses/go.mongodb.org/mongo-driver/v2@v2.9.1/LICENSE) |
| `golang.org/x/crypto` | `v0.57.0` | [LICENSE](third_party/licenses/golang.org/x/crypto@v0.57.0/LICENSE) |
| `golang.org/x/sync` | `v0.23.0` | [LICENSE](third_party/licenses/golang.org/x/sync@v0.23.0/LICENSE) |
| `golang.org/x/sys` | `v0.48.0` | [LICENSE](third_party/licenses/golang.org/x/sys@v0.48.0/LICENSE) |
| `golang.org/x/text` | `v0.42.0` | [LICENSE](third_party/licenses/golang.org/x/text@v0.42.0/LICENSE) |
