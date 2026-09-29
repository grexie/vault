FROM golang:1.26.8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make assets && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /remote-ssh-agent ./cmd/remote-ssh-agent
RUN mkdir -p /data && chown 65532:65532 /data && chmod 0700 /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /remote-ssh-agent /remote-ssh-agent
COPY --from=build --chown=65532:65532 /data /data
EXPOSE 8787
ENTRYPOINT ["/remote-ssh-agent"]
CMD ["serve", "--listen", "0.0.0.0:8787", "--data", "/data"]
