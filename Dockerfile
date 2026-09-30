FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c AS extension-build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY extension ./extension
COPY scripts/build-wallet-extension.mjs ./scripts/build-wallet-extension.mjs
COPY web/static ./web/static
COPY internal/browserwallet/native.go ./internal/browserwallet/native.go
RUN node scripts/build-wallet-extension.mjs

FROM golang:1.26.8@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=extension-build /src/extension/dist ./extension/dist
ARG VERSION=dev
RUN make assets SKIP_EXTENSION_BUILD=1 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /vault ./cmd/vault

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /vault /vault
COPY --from=build /src/LICENSE /src/THIRD_PARTY_NOTICES.md /licenses/
COPY --from=build /src/third_party /licenses/third_party
LABEL org.opencontainers.image.source="https://github.com/grexie/vault"
EXPOSE 8791
ENTRYPOINT ["/vault"]
CMD ["cloud", "--listen", "0.0.0.0:8791"]
