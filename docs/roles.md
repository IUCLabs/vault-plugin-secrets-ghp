# roles

A role defines what each minted token can do: its token type, App installation,
repositories, scopes and lease TTLs.

| Method   | Path               |
|----------|--------------------|
| `POST`   | `/ghp/roles/:name` |
| `GET`    | `/ghp/roles/:name` |
| `DELETE` | `/ghp/roles/:name` |
| `LIST`   | `/ghp/roles`       |

## Create or update a role

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | string | (required) | Role name, part of the URL. Lower-cased. |
| `token_type` | string | `agent` | `agent` (backed by a ghp App installation) or `proxy` (backed by OAuth). |
| `installation_id` | int | | GitHub App installation id. Required when `token_type=agent`; ignored for `proxy`. |
| `app_record_id` | string | `""` | ghp App record id (UUID) for agent tokens. Empty selects ghp's default App. |
| `repositories` | comma list | `[]` | Repositories (`owner/name`) the token is limited to. Empty means every repository in the installation. |
| `scopes` | comma list | `[]` | `permission:level` entries, level `read` or `write`, e.g. `contents:read,pull_requests:write`. Empty means no permission limit. |
| `session_prefix` | string | `vault` | Prefix of the ghp session id given to each token (`<prefix>-<role>-<random>`), so tokens are easy to spot in ghp. |
| `ttl` | duration | mount default | Default lease TTL. |
| `max_ttl` | duration | mount max | Maximum lease TTL. Also used as the token's ghp-side expiry. |

Validation:

- `ttl` must not exceed `max_ttl`.
- A scope without a `:`, with an empty permission, or with a level other than
  `read`/`write` is rejected.
- The same permission at two different levels (`contents:read,contents:write`)
  is rejected. Exact duplicates are removed.

On update, any parameter you leave out keeps its stored value.

### Examples

Agent token for one installation, limited to two repositories:

```sh
vault write ghp/roles/ci \
    token_type=agent \
    installation_id=4242 \
    repositories=example/app,example/tools \
    scopes=contents:read,pull_requests:write \
    ttl=1h max_ttl=8h
```

Agent token pinned to a specific ghp App record, no repository or scope limit:

```sh
vault write ghp/roles/release \
    installation_id=4242 \
    app_record_id=3f1c2a9e-4b5d-4e6f-8a7b-0c1d2e3f4a5b \
    ttl=30m max_ttl=2h
```

Proxy token:

```sh
vault write ghp/roles/proxy token_type=proxy scopes=contents:read ttl=30m max_ttl=4h
```

## Read a role

`ttl` and `max_ttl` are returned in seconds.

```sh
$ vault read ghp/roles/ci
Key                Value
---                -----
app_record_id      n/a
installation_id    4242
max_ttl            28800
repositories       [example/app example/tools]
scopes             [contents:read pull_requests:write]
session_prefix     vault
token_type         agent
ttl                3600
```

## List roles

```sh
$ vault list ghp/roles
Keys
----
ci
proxy
release
```

## Delete a role

```sh
vault delete ghp/roles/ci
```

Tokens already minted from the role stay valid until their leases end.
