package ghp

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const ghpTokenType = "ghp_token"

func (b *ghpBackend) ghpTokenSecret() *framework.Secret {
	return &framework.Secret{
		Type: ghpTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "The ghp access token value.",
			},
			"token_id": {
				Type:        framework.TypeString,
				Description: "The ghp token id (used for revocation).",
			},
			"token_type": {
				Type:        framework.TypeString,
				Description: "The ghp token type (agent or proxy).",
			},
			"repositories": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Repositories the token is scoped to.",
			},
			"scopes": {
				Type:        framework.TypeKVPairs,
				Description: "Permission:level scopes granted to the token.",
			},
			"expires_at": {
				Type:        framework.TypeString,
				Description: "The ghp server-side expiry timestamp (RFC3339), if any.",
			},
			"session_id": {
				Type:        framework.TypeString,
				Description: "The ghp session id assigned to the token.",
			},
			"base_url": {
				Type:        framework.TypeString,
				Description: "The ghp base URL the token authenticates against.",
			},
		},
		Revoke: b.secretRevoke,
		Renew:  b.secretRenew,
	}
}

// secretRevoke deletes the minted ghp token via the admin API. Returning an
// error lets Vault retry; a token already gone (404) is treated as success
// inside RevokeToken so retries converge.
func (b *ghpBackend) secretRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenID, err := internalString(req.Secret.InternalData, "token_id")
	if err != nil {
		return nil, err
	}

	client, err := b.clientFor(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if err := client.RevokeToken(ctx, tokenID); err != nil {
		return nil, fmt.Errorf("revoking ghp token %q: %w", tokenID, err)
	}
	return nil, nil
}

// secretRenew extends the Vault lease; the token material is unchanged. The
// ghp-side duration was set to the lease ceiling at mint time, so a renew within
// max_ttl simply postpones deletion without outliving the server-side expiry.
func (b *ghpBackend) secretRenew(_ context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{Secret: req.Secret}, nil
}

func internalString(data map[string]interface{}, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("secret is missing internal %s data", key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", errors.New("secret internal " + key + " data is not a string")
	}
	return s, nil
}
