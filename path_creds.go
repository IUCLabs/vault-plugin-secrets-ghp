package ghp

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *ghpBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ghp",
			OperationSuffix: "credentials",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to mint a token for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathCredentialsRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Mint a short-lived ghp token from a role.",
		HelpDescription: "Reading this path mints a new, lease-bound ghp token for the role; the token is deleted from ghp when the lease is revoked.",
	}
}

func (b *ghpBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}

	client, err := newClient(config)
	if err != nil {
		return nil, err
	}

	ttl, maxTTL := b.resolveTTLs(role.TTL, role.MaxTTL)

	suffix, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("generating session id suffix: %w", err)
	}
	sessionID := fmt.Sprintf("%s-%s-%s", role.sessionPrefix(), roleName, suffix[:8])

	createReq := createTokenRequest{
		Type:         role.tokenType(),
		Repositories: role.Repositories,
		Scopes:       scopeString(role.Scopes),
		// Bound the ghp-side expiry to the lease ceiling so the token self-expires
		// even if lease revocation never reaches ghp; the lease remains primary.
		Duration:  maxTTL.String(),
		SessionID: sessionID,
	}
	if role.tokenType() == tokenTypeAgent {
		createReq.InstallationID = role.InstallationID
		createReq.AppRecordID = role.AppRecordID
	}

	out, err := client.CreateToken(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("minting ghp token: %w", err)
	}

	internal := map[string]interface{}{
		"token_id": out.ID,
	}
	external := map[string]interface{}{
		"token":        out.Token,
		"token_id":     out.ID,
		"token_type":   out.Type,
		"repositories": out.Repositories,
		"scopes":       out.Scopes,
		"expires_at":   out.ExpiresAt,
		"session_id":   out.SessionID,
		"base_url":     config.BaseURL,
	}

	resp := b.Secret(ghpTokenType).Response(external, internal)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = true
	return resp, nil
}

// resolveTTLs clamps a role's TTL/MaxTTL against the mount and system limits.
func (b *ghpBackend) resolveTTLs(roleTTL, roleMaxTTL time.Duration) (ttl, maxTTL time.Duration) {
	sysMaxTTL := b.System().MaxLeaseTTL()
	maxTTL = roleMaxTTL
	if maxTTL <= 0 || maxTTL > sysMaxTTL {
		maxTTL = sysMaxTTL
	}
	ttl = roleTTL
	if ttl <= 0 {
		ttl = b.System().DefaultLeaseTTL()
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL
}
