# Hosted service deployment

`docker-stack.yml` is the Grexie deployment example. It uses existing private `mongo` and `traefik` overlays, a single cloud replica, an unprivileged read-only container and no published application port. All public traffic reaches the existing bastion and HTTPS ingress. Adapt the hostname, placement, network and database transport to your own infrastructure.

Create `vault_storage_key_v1` from exactly 32 random bytes and `vault_mongodb_uri_v1` from a locally provisioned MongoDB URI. Supply both using `docker secret create NAME -` through protected input; never put their contents in this directory, environment variables, CLI arguments or Git. Keep the storage key backed up independently. The example explicitly uses the existing trusted private MongoDB transport; use MongoDB TLS and authentication outside that isolated deployment.

Set `VAULT_IMAGE` to the exact built release image. Set `VAULT_TRUSTED_PROXIES` to the current ingress task/virtual IPs as `/32` (or `/128`) entries. Do not trust the entire shared overlay. If the ingress task gets a new address, refresh these entries before it serves authentication traffic. Vault rejects malformed client addresses from trusted peers and ignores client-controlled forwarding headers from all other peers. The ingress must sanitize `X-Real-IP`, `X-Forwarded-For` and related headers, with unrestricted forwarded-header trust disabled.

```sh
VAULT_IMAGE=grexie-vault:RELEASE \
VAULT_TRUSTED_PROXIES=INGRESS_TASK_IP/32,INGRESS_VIRTUAL_IP/32 \
docker stack deploy --resolve-image never -c deploy/docker-stack.yml grexie-vault
```

Verify the image ID on the running task, one healthy replica, HTTPS certificate and redirects, `/api/v1/health`, security headers, public setup and skill pages, and passkey behavior through the public origin. Keep the user-controlled signing daemon on the user's machine; it is not part of this stack. An existing Remote SSH Agent installation can continue during migration.
