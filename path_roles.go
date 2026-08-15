package ghp

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const roleStoragePrefix = "role/"

const (
	tokenTypeAgent = "agent"
	tokenTypeProxy = "proxy"
)

// defaultSessionPrefix labels each minted token's ghp session id so leaked or
// orphaned tokens are recognisable in ghp's UI/audit log.
const defaultSessionPrefix = "vault"

// ghpRole binds a ghp token type, App installation and scope set to a TTL
// policy. Each read of creds/<name> mints a unique, lease-bound token for it.
type ghpRole struct {
	// TokenType is "agent" (default) or "proxy". Agent tokens are backed by a
	// ghp App installation and are the natural fit for a service credential.
	TokenType string `json:"token_type"`
	// InstallationID is the ghp/GitHub App installation id (required for agent
	// tokens; ghp rejects agent tokens without one).
	InstallationID int64 `json:"installation_id"`
	// AppRecordID optionally pins an agent token to a specific ghp App record
	// (UUID); empty selects ghp's default/only app.
	AppRecordID string `json:"app_record_id"`
	// Repositories optionally restricts the token to named repositories; empty
	// is open-scoped (all repositories in the installation).
	Repositories []string `json:"repositories"`
	// Scopes are ghp permission:level entries; empty is open-scoped.
	Scopes []string `json:"scopes"`
	// SessionPrefix prefixes each minted token's ghp session id.
	SessionPrefix string        `json:"session_prefix"`
	TTL           time.Duration `json:"ttl"`
	MaxTTL        time.Duration `json:"max_ttl"`
}

func (r *ghpRole) sessionPrefix() string {
	if r.SessionPrefix != "" {
		return r.SessionPrefix
	}
	return defaultSessionPrefix
}

func (r *ghpRole) tokenType() string {
	if r.TokenType != "" {
		return r.TokenType
	}
	return tokenTypeAgent
}

func pathRole(b *ghpBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ghp",
			OperationSuffix: "role",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
				Required:    true,
			},
			"token_type": {
				Type:        framework.TypeString,
				Description: "ghp token type to mint: \"agent\" (default) or \"proxy\".",
				Default:     tokenTypeAgent,
			},
			"installation_id": {
				Type:        framework.TypeInt64,
				Description: "ghp App installation id the minted agent token is bound to (required for agent tokens).",
			},
			"app_record_id": {
				Type:        framework.TypeString,
				Description: "Optional ghp App record id (UUID) to pin agent tokens to; empty selects ghp's default app.",
			},
			"repositories": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional repositories the token is restricted to; empty is open-scoped (all repositories).",
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional ghp permission:level scopes (e.g. contents:read,pull_requests:write); empty is open-scoped.",
			},
			"session_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix for the ghp session id of each minted token (default \"vault\").",
				Default:     defaultSessionPrefix,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default lease TTL for tokens minted from this role.",
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum lease TTL for tokens minted from this role.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		ExistenceCheck:  b.pathRoleExistenceCheck,
		HelpSynopsis:    "Manage roles that mint short-lived ghp tokens.",
		HelpDescription: "Each read of creds/<name> mints a unique, lease-bound ghp token for the role's installation with the role's scopes.",
	}
}

func pathRolesList(b *ghpBackend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ghp",
			OperationSuffix: "roles",
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRolesList},
		},
		HelpSynopsis:    "List roles.",
		HelpDescription: "List the token-minting roles configured on this backend.",
	}
}

func (b *ghpBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *ghpBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"token_type":      role.tokenType(),
			"installation_id": role.InstallationID,
			"app_record_id":   role.AppRecordID,
			"repositories":    role.Repositories,
			"scopes":          role.Scopes,
			"session_prefix":  role.sessionPrefix(),
			"ttl":             int64(role.TTL.Seconds()),
			"max_ttl":         int64(role.MaxTTL.Seconds()),
		},
	}, nil
}

func (b *ghpBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &ghpRole{}
	}

	if v, ok := data.GetOk("token_type"); ok {
		role.TokenType = v.(string)
	}
	if v, ok := data.GetOk("installation_id"); ok {
		role.InstallationID = v.(int64)
	}
	if v, ok := data.GetOk("app_record_id"); ok {
		role.AppRecordID = v.(string)
	}
	if v, ok := data.GetOk("repositories"); ok {
		role.Repositories = v.([]string)
	}
	if v, ok := data.GetOk("scopes"); ok {
		scopes, serr := normalizeScopes(v.([]string))
		if serr != nil {
			return logical.ErrorResponse(serr.Error()), nil
		}
		role.Scopes = scopes
	}
	if v, ok := data.GetOk("session_prefix"); ok {
		role.SessionPrefix = v.(string)
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}

	switch role.tokenType() {
	case tokenTypeAgent:
		if role.InstallationID == 0 {
			return logical.ErrorResponse("installation_id is required for agent tokens"), nil
		}
	case tokenTypeProxy:
		// proxy tokens are OAuth-backed; installation_id/app_record_id do not apply.
	default:
		return logical.ErrorResponse("token_type must be %q or %q", tokenTypeAgent, tokenTypeProxy), nil
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl must not exceed max_ttl"), nil
	}

	return nil, setJSON(ctx, req.Storage, roleStoragePrefix+name, role)
}

func (b *ghpBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, roleStoragePrefix+data.Get("name").(string))
}

func (b *ghpBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *ghpBackend) getRole(ctx context.Context, s logical.Storage, name string) (*ghpRole, error) {
	if name == "" {
		return nil, errors.New("missing role name")
	}
	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &ghpRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}
