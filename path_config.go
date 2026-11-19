package ghp

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// ghpConfig is the connection to ghp plus the seeded service token the engine
// authenticates with to mint and revoke tokens.
type ghpConfig struct {
	BaseURL               string `json:"base_url"`
	AdminToken            string `json:"admin_token"`
	CACert                string `json:"ca_cert"`
	TLSSkipVerify         bool   `json:"tls_skip_verify"`
	RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
}

func pathConfig(b *ghpBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "ghp",
			OperationSuffix: "config",
		},
		Fields: map[string]*framework.FieldSchema{
			"base_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the ghp server, e.g. https://ghp.example.com. Required.",
			},
			"admin_token": {
				Type:        framework.TypeString,
				Description: "ghp service token (ghpsvc_...) sent as a bearer credential; ghp treats it as a synthetic admin. Write-only, never returned.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Admin Token",
					Sensitive: true,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM CA certificate that signed the ghp server's TLS certificate.",
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Skip TLS verification of the ghp server (not recommended).",
				Default:     false,
			},
			"request_timeout_seconds": {
				Type:        framework.TypeInt,
				Description: "HTTP timeout in seconds for calls to ghp (default 30).",
				Default:     30,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the connection to ghp and the seeded service token.",
		HelpDescription: "Configure the ghp URL, TLS settings, and the service token the engine authenticates with. Roles then mint scoped tokens with this credential.",
	}
}

func (b *ghpBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *ghpBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	// admin_token is deliberately never returned.
	return &logical.Response{
		Data: map[string]interface{}{
			"base_url":                config.BaseURL,
			"tls_skip_verify":         config.TLSSkipVerify,
			"request_timeout_seconds": config.RequestTimeoutSeconds,
		},
	}, nil
}

func (b *ghpBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = &ghpConfig{}
	}

	if v, ok := data.GetOk("base_url"); ok {
		config.BaseURL = v.(string)
	}
	if v, ok := data.GetOk("admin_token"); ok {
		config.AdminToken = v.(string)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		config.CACert = v.(string)
	}
	if v, ok := data.GetOk("tls_skip_verify"); ok {
		config.TLSSkipVerify = v.(bool)
	}
	if v, ok := data.GetOk("request_timeout_seconds"); ok {
		config.RequestTimeoutSeconds = v.(int)
	} else if req.Operation == logical.CreateOperation {
		config.RequestTimeoutSeconds = data.Get("request_timeout_seconds").(int)
	}

	if config.BaseURL == "" {
		return logical.ErrorResponse("base_url is required"), nil
	}
	if config.AdminToken == "" {
		return logical.ErrorResponse("admin_token is required"), nil
	}

	// Verify the seeded token authenticates as a ghp admin before storing it, so
	// misconfiguration fails fast rather than at first mint.
	client, err := newClient(config)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if err := client.VerifyAdmin(ctx); err != nil {
		return logical.ErrorResponse("verifying ghp admin_token: %s", err), nil
	}

	return nil, setJSON(ctx, req.Storage, configStoragePath, config)
}

func (b *ghpBackend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, configStoragePath)
}

func getConfig(ctx context.Context, s logical.Storage) (*ghpConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	config := &ghpConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}
	return config, nil
}

// setJSON stores a value as a JSON storage entry.
func setJSON(ctx context.Context, s logical.Storage, key string, value interface{}) error {
	entry, err := logical.StorageEntryJSON(key, value)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}
