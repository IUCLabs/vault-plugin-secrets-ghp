# creds

Reading `creds/:name` mints a new ghp token from the role and returns it with a
Vault lease. Revoking the lease deletes the token from ghp.

| Method       | Path               |
|--------------|--------------------|
| `GET`/`POST` | `/ghp/creds/:name` |

## Mint a token

The engine calls ghp's `POST /api/tokens` with the role's token type,
installation, repositories and scopes. The token's ghp-side duration is set to
the lease's `max_ttl`, so it expires on its own even if revocation never
reaches ghp.

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

### Response fields

| Name | Description |
|------|-------------|
| `token` | The token value. Only returned here; ghp never shows it again. |
| `token_id` | ghp token id, used to delete the token on revoke. |
| `token_type` | `agent` or `proxy`. |
| `repositories` | Repositories the token is limited to. |
| `scopes` | Permission to level map granted to the token. |
| `expires_at` | ghp-side expiry (RFC 3339). |
| `session_id` | ghp session id, `<session_prefix>-<role>-<random>`. |
| `base_url` | ghp URL the token works against. |

## Renew

Renewing extends the lease up to the role's `max_ttl`. The token itself does
not change.

```sh
vault lease renew ghp/creds/ci/Yx7...
```

## Revoke

Revoking the lease (or letting it expire) calls `DELETE /api/tokens/:id` on
ghp. A 404 from ghp counts as success, so retries are safe.

```sh
vault lease revoke ghp/creds/ci/Yx7...

# every token minted from one role
vault lease revoke -prefix ghp/creds/ci
```
