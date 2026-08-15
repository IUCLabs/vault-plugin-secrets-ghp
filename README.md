# vault-plugin-secrets-ghp

A Vault / OpenBao secrets engine that mints **ephemeral, scoped ghp access
tokens** on demand.

## Why

Machine callers of [ghp](https://git.unkin.net/unkin/ghp) (the GitHub proxy) —
CI identities, agents, ... — should never hold standing ghp tokens: a leaked
token is valid until someone notices and revokes it. This engine removes standing
tokens entirely:

- You seed it once with a single ghp **service token** (`ghpsvc_...`) that ghp
  treats as a synthetic site admin.
- A **role** binds a ghp App installation (and optional scopes/repositories) to a
  set of TTLs.
- Each read of `creds/<role>` mints a fresh token via `POST /api/tokens`, bound
  to a Vault lease, and **deletes it from ghp when the lease is revoked or
  expires** (`DELETE /api/tokens/{id}`).

### Why a static service token, not a rotated root credential

ghp service tokens are configured on the ghp server (`auth.service_tokens` /
`GHP_AUTH_SERVICE_TOKENS`) and authenticate as a synthetic admin with no database
row. There is nothing for the engine to rotate in place, so — unlike the sibling
`vault-plugin-secrets-gitea` engine — this backend deliberately has **no
`config/rotate-root` path**. The service token is supplied and rotated through
Vault config by the operator.

### Server-side expiry *and* the Vault lease

Unlike Gitea tokens, ghp tokens **do** expire server-side. Each mint sets a
`duration` equal to the lease ceiling (`max_ttl`), so the token self-expires even
if lease revocation never reaches ghp. The Vault lease remains the primary
expiry: on revoke or `max_ttl`, the engine issues `DELETE /api/tokens/{id}`. A
delete that returns 404 (token already gone) is treated as success, so revocation
is idempotent and Vault's retries converge.

## Paths

| Path | Description |
|------|-------------|
| `config` | ghp `base_url` + TLS settings + seeded `admin_token` service token. Verifies the token is a ghp admin on write. |
| `roles/<name>` | Mint policy: `token_type`, `installation_id`, `app_record_id`, `repositories`, `scopes`, `session_prefix`, `ttl`, `max_ttl`. |
| `roles` | List roles. |
| `creds/<role>` | Read to mint a short-lived, lease-bound ghp token for the role. |

## Token types

- **agent** (default) — backed by a ghp App installation. Requires
  `installation_id`; `app_record_id` optionally pins a specific ghp App record
  (UUID). This is the natural fit for a service credential and works with the
  synthetic-admin service token.
- **proxy** — OAuth-backed. Included for completeness; note a service-token
  identity generally has no linked GitHub OAuth token, so proxy mints require ghp
  to be configured accordingly.

## Scopes

`scopes` is a comma-separated list of `permission:level` entries (matching ghp's
`token.ParseScopeString`), where `level` is `read` or `write` and `permission` is
a GitHub App permission key (`contents`, `pull_requests`, `issues`, ...). An
empty `scopes` is **open-scoped**. Likewise an empty `repositories` grants all
repositories in the installation.

## Usage

```sh
vault secrets enable -path=ghp vault-plugin-secrets-ghp

# Seed with a ghp service token (ghpsvc_...).
vault write ghp/config \
  base_url=https://ghp.unkin.net \
  admin_token='ghpsvc_...' \
  ca_cert=@ghp-ca.pem

# A role that mints 1h agent tokens for App installation 4242, scoped to
# repo contents + PRs.
vault write ghp/roles/agent token_type=agent installation_id=4242 \
  scopes=contents:read,pull_requests:write ttl=1h max_ttl=24h

# Mint one. The token is deleted from ghp when the lease is revoked.
vault read ghp/creds/agent
```

## Development

```sh
make build      # build the plugin binary into ./dist
make test       # unit tests (race)
make e2e        # full lifecycle vs mock ghp on Vault + OpenBao (Docker)
make rpm        # build Vault + OpenBao RPMs via nfpm
```

Releases are tag-driven (`make patch|minor|major`): a Woodpecker pipeline builds
the Vault and OpenBao RPMs and uploads them to the internal artifactapi yum repo.

## Deployment (out of scope for this repo; documented for the operator)

Live registration mirrors the sibling `vault-plugin-secrets-gitea` /
`vault-plugin-secrets-rancher` engines:

1. **Release**: tag `v0.1.0` (`make minor` from `v0.0.0`). CI publishes
   `rpm-internal/files/Packages/{vault,openbao}-plugin-secrets-ghp-<ver>-1.x86_64.rpm`.
2. **terraform-vault**: plugin catalog entry with the release `sha256`, engine
   policies, and `ghp_secret_backend` + `ghp_secret_backend_role` module
   instances (via the companion terraform provider).
3. **Seed the service token in KV** before the backend module applies, e.g.
   `kv/service/vault/au/syd1/secret_backend/ghp/config` with `admin_token` set to
   a ghp service token configured in `GHP_AUTH_SERVICE_TOKENS`.
4. **Reload after a binary upgrade**:
   `vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-ghp`.
   Bump the RPM version in puppet-prod and the catalog `sha256` in terraform-vault
   *together* so the on-disk binary stays in lockstep with the catalog.
