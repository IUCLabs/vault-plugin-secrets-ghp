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

Release assets download through artifactapi's GitHub proxy, which serves
`https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-ghp/releases/download/<tag>/<file>`.
Each method below ends with `SHA256` set for [registration](#register-and-enable).
With OpenBao, use `bao` in place of `vault`.

```sh
TAG=vX.Y.Z  # the release to install
V=${TAG#v}
BASE=https://artifactapi.k8s.syd1.au.unkin.net/api/v1/remote/github/IUCLabs/vault-plugin-secrets-ghp/releases/download/$TAG
```

### RPM

`vault-plugin-secrets-ghp` installs `/usr/libexec/vault-plugins/vault-plugin-secrets-ghp`;
`openbao-plugin-secrets-ghp` installs it in `/usr/libexec/openbao-plugins/`.
Set the server's `plugin_directory` to that directory.

```sh
dnf install vault-plugin-secrets-ghp  # from a yum repo carrying it, or from the release:
dnf install "$BASE/vault-plugin-secrets-ghp-$V-1.x86_64.rpm"  # openbao-plugin-secrets-ghp-$V-1.x86_64.rpm for OpenBao

SHA256=$(sha256sum /usr/libexec/vault-plugins/vault-plugin-secrets-ghp | cut -d' ' -f1)
```

### Released binary

`vault-plugin-secrets-ghp_<version>_SHA256SUMS` lists the binary and the RPMs, and
`SHA256SUMS.sig` is its detached signature by the IUCLabs release GPG key.

```sh
curl -fLO "$BASE/vault-plugin-secrets-ghp_${V}_linux_amd64"
curl -fLO "$BASE/vault-plugin-secrets-ghp_${V}_SHA256SUMS"
curl -fLO "$BASE/vault-plugin-secrets-ghp_${V}_SHA256SUMS.sig"
gpg --verify "vault-plugin-secrets-ghp_${V}_SHA256SUMS.sig" "vault-plugin-secrets-ghp_${V}_SHA256SUMS"
sha256sum --check --ignore-missing "vault-plugin-secrets-ghp_${V}_SHA256SUMS"

install -m 0755 "vault-plugin-secrets-ghp_${V}_linux_amd64" <plugin_directory>/vault-plugin-secrets-ghp
SHA256=$(sha256sum <plugin_directory>/vault-plugin-secrets-ghp | cut -d' ' -f1)
```

### Kubernetes image volume

`ghcr.io/iuclabs/vault-plugin-secrets-ghp:<tag>` is a `FROM scratch` image holding only
`/vault-plugin-secrets-ghp`. Mount it read-only into the Vault/OpenBao container with an
[image volume](https://kubernetes.io/docs/concepts/storage/volumes/#image):
Kubernetes 1.31+ with the `ImageVolume` feature gate (beta, on by default from
1.33). Vault and OpenBao only run a binary that sits directly in
`plugin_directory`, not in a subdirectory, so mount the file itself with
`subPath`, which on image volumes needs 1.33+.

```yaml
spec:
  containers:
    - name: vault
      volumeMounts:
        - name: plugin-ghp
          mountPath: /vault/plugins/vault-plugin-secrets-ghp  # <plugin_directory>/vault-plugin-secrets-ghp
          subPath: vault-plugin-secrets-ghp
          readOnly: true
  volumes:
    - name: plugin-ghp
      image:
        reference: ghcr.io/iuclabs/vault-plugin-secrets-ghp:vX.Y.Z
        pullPolicy: IfNotPresent
```

The image holds the released binary, so its sha256 is the `linux_amd64` line
of `SHA256SUMS`:

```sh
SHA256=$(curl -fsSL "$BASE/vault-plugin-secrets-ghp_${V}_SHA256SUMS" | awk '/_linux_amd64$/ {print $1}')
```

### From source

```sh
make build  # writes ./dist/vault-plugin-secrets-ghp
```

Copy it into `plugin_directory` and take `SHA256` from `sha256sum` as above.

### Register and enable

```sh
vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-ghp
vault secrets enable -path=ghp vault-plugin-secrets-ghp
```

After replacing the binary, register the new sha256 and reload the plugin:

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
