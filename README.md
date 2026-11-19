# vault-plugin-secrets-ghp

A HashiCorp Vault / OpenBao secrets engine that mints short-lived, scoped
**[ghp](https://github.com/goodtune/ghp)** access tokens on demand. ghp is a GitHub proxy that issues its own
tokens in front of GitHub App installations.

## Why use this plugin?

Machine callers (CI jobs, agents, services) should not hold long-lived tokens.
The engine is seeded once with a ghp **service token** (`ghpsvc_...`). Each read
of `creds/<role>` mints a fresh token scoped by the role, ties it to a Vault
lease, and deletes it from ghp when the lease expires or is revoked. Every token
also carries a ghp-side expiry equal to the lease's `max_ttl`, so it expires even
if revocation never reaches ghp.

To manage the engine from Terraform, use the companion provider
[terraform-provider-vault-secrets-ghp](https://github.com/IUCLabs/terraform-provider-vault-secrets-ghp).

## Requirements

- HashiCorp Vault or OpenBao (tested against Vault 1.18 and OpenBao)
- Go 1.25+ to build from source
- A ghp server with a service token configured (`GHP_AUTH_SERVICE_TOKENS`)

## Installation

Install the x86_64 RPM (vault or openbao flavour) from the
[releases page](https://github.com/IUCLabs/vault-plugin-secrets-ghp/releases), or build one:

```sh
make build   # writes ./dist/vault-plugin-secrets-ghp
```

Copy it into the server's `plugin_directory` (`$PLUGIN_DIR` below must match
that setting in the server config), then register and enable it.
The same commands work with OpenBao: use `bao` instead of `vault`.

```sh
SHA256=$(sha256sum "$PLUGIN_DIR/vault-plugin-secrets-ghp" | cut -d' ' -f1)

vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-ghp
vault secrets enable -path=ghp vault-plugin-secrets-ghp
```

After you replace the binary, re-register it with the new sha256 and reload it:

```sh
vault write sys/plugins/reload/backend plugin=vault-plugin-secrets-ghp
```

## Configuration

Point the engine at ghp and seed it with the service token. The engine checks
that the token authenticates as a ghp admin before it saves the config.

```sh
vault write ghp/config \
    base_url=https://ghp.example.com \
    admin_token="$GHP_SERVICE_TOKEN" \
    ca_cert=@ghp-ca.pem
```

`admin_token` is write-only and is never returned on read.

## Usage

Create a role. This one mints 1h **agent** tokens for App installation 4242,
limited to two repositories:

```sh
vault write ghp/roles/ci \
    token_type=agent \
    installation_id=4242 \
    repositories=example/app,example/tools \
    scopes=contents:read,pull_requests:write \
    ttl=1h max_ttl=24h
```

Mint a token:

```sh
$ vault read ghp/creds/ci
Key                Value
---                -----
lease_id           ghp/creds/ci/Yx7...
lease_duration     1h
lease_renewable    true
base_url           https://ghp.example.com
expires_at         2026-01-01T12:00:00Z
repositories       [example/app example/tools]
scopes             map[contents:read pull_requests:write]
session_id         vault-ci-1a2b3c4d
token              <ghp token>
token_id           0b5f...
token_type         agent
```

Revoke it early; this deletes the token from ghp:

```sh
vault lease revoke ghp/creds/ci/Yx7...
```

### Token types

- `agent` (default): backed by a ghp App installation. Requires
  `installation_id`; `app_record_id` optionally pins a specific ghp App record.
- `proxy`: backed by OAuth. The service-token identity normally has no linked
  GitHub OAuth token, so proxy roles only work if ghp is set up for that.

### Scopes

`scopes` is a comma-separated list of `permission:level` entries. `level` is
`read` or `write`; `permission` is a GitHub App permission key (`contents`,
`pull_requests`, `issues`, ...). If `scopes` is empty, the token is not limited
by permission. If `repositories` is empty, the token covers every repository in
the installation.

## Documentation

Full path reference:

- [`config`](docs/config.md): connection to ghp and the seeded service token
- [`roles`](docs/roles.md): token-minting roles
- [`creds`](docs/creds.md): mint, renew and revoke tokens

## Development

```sh
make build   # build ./dist/vault-plugin-secrets-ghp
make test    # unit tests
make lint    # go vet
make e2e     # full lifecycle against a mock ghp on Vault and OpenBao (Docker)
```

## License

[MIT](LICENSE)
