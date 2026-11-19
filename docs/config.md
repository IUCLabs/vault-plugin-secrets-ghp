# config

Holds the connection to ghp and the service token the engine uses to mint and
delete tokens. There is one config per mount.

| Method   | Path         |
|----------|--------------|
| `POST`   | `/ghp/config` |
| `GET`    | `/ghp/config` |
| `DELETE` | `/ghp/config` |

## Write config

On every write the engine calls ghp with `admin_token` and rejects the config
unless the token authenticates as a ghp admin. A bad URL, CA or token fails here
instead of at the first mint.

### Parameters

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `base_url` | string | (required) | Base URL of the ghp server, e.g. `https://ghp.example.com`. |
| `admin_token` | string | (required) | ghp service token (`ghpsvc_...`), sent as a bearer token. ghp treats it as an admin. Write-only. |
| `ca_cert` | string | `""` | PEM CA certificate that signed the ghp server's TLS certificate. Write-only. |
| `tls_skip_verify` | bool | `false` | Skip TLS verification of the ghp server. Not recommended. |
| `request_timeout_seconds` | int | `30` | HTTP timeout in seconds for calls to ghp. |

On update, any parameter you leave out keeps its stored value.

### Example

```sh
vault write ghp/config \
    base_url=https://ghp.example.com \
    admin_token="$GHP_SERVICE_TOKEN" \
    ca_cert=@ghp-ca.pem \
    request_timeout_seconds=15
```

## Read config

Returns everything except `admin_token` and `ca_cert`.

```sh
$ vault read ghp/config
Key                        Value
---                        -----
base_url                   https://ghp.example.com
request_timeout_seconds    15
tls_skip_verify            false
```

## Delete config

```sh
vault delete ghp/config
```

Leases that already exist cannot be revoked until a config is written again.

## Rotating the service token

ghp service tokens are defined in the ghp server's configuration, so the engine
has no `config/rotate-root` path. To rotate, add the new token on the ghp server,
write it here, then remove the old token from ghp:

```sh
vault write ghp/config admin_token="$NEW_GHP_SERVICE_TOKEN"
```
