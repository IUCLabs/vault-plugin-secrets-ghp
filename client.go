package ghp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// ghpClient talks to the ghp admin API using the seeded service token as a
// bearer credential. ghp matches the token against its configured service-token
// set and grants a synthetic admin session, which is required to mint agent
// tokens and to revoke any user's token.
type ghpClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// createTokenRequest is ghp's POST /api/tokens body. Only the fields the engine
// sets are included; omitempty keeps the wire payload minimal.
type createTokenRequest struct {
	Type           string   `json:"type,omitempty"`
	AppRecordID    string   `json:"app_record_id,omitempty"`
	Repositories   []string `json:"repositories,omitempty"`
	InstallationID int64    `json:"installation_id,omitempty"`
	Scopes         string   `json:"scopes,omitempty"`
	Duration       string   `json:"duration,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
}

// createTokenResponse mirrors the subset of ghp's 201 response the engine reads.
// The token value is only ever returned here, at creation.
type createTokenResponse struct {
	Token        string            `json:"token"`
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Repositories []string          `json:"repositories"`
	Scopes       map[string]string `json:"scopes"`
	ExpiresAt    string            `json:"expires_at"`
	SessionID    string            `json:"session_id"`
}

func newClient(cfg *ghpConfig) (*ghpClient, error) {
	if cfg == nil {
		return nil, errors.New("ghp client configuration is nil")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("base_url is required")
	}
	if cfg.AdminToken == "" {
		return nil, errors.New("admin_token is required")
	}

	timeout := defaultHTTPTimeout
	if cfg.RequestTimeoutSeconds > 0 {
		timeout = time.Duration(cfg.RequestTimeoutSeconds) * time.Second
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec // opt-in via config
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("ca_cert is not a valid PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}

	return &ghpClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		token:   cfg.AdminToken,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}, nil
}

// errNotFound flags a 404 so callers can treat absence as non-fatal.
var errNotFound = errors.New("not found")

// CreateToken mints a new ghp token and returns the full response. The service
// token's synthetic-admin session authorises agent-token creation and any scope.
func (c *ghpClient) CreateToken(ctx context.Context, req createTokenRequest) (*createTokenResponse, error) {
	var out createTokenResponse
	if err := c.do(ctx, http.MethodPost, "/api/tokens", req, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, errors.New("ghp returned an empty token value")
	}
	if out.ID == "" {
		return nil, errors.New("ghp returned an empty token id")
	}
	return &out, nil
}

// RevokeToken deletes a ghp token by its id. A missing token (404) is treated as
// success so revocation is idempotent and Vault's retries converge.
func (c *ghpClient) RevokeToken(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	err := c.do(ctx, http.MethodDelete, "/api/tokens/"+id, nil, nil)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}

// VerifyAdmin confirms the seeded service token authenticates as a ghp admin by
// calling an admin-only endpoint. 401 means the token is invalid; 403 means it
// authenticated but is not an admin. Used to fail config writes fast.
func (c *ghpClient) VerifyAdmin(ctx context.Context) error {
	err := c.do(ctx, http.MethodGet, "/api/users", nil, nil)
	if err == nil {
		return nil
	}
	if errors.Is(err, errUnauthorized) {
		return errors.New("ghp rejected the admin_token (401); it is not a configured service token")
	}
	if errors.Is(err, errForbidden) {
		return errors.New("the admin_token authenticated but is not a ghp admin (403); a service token is required")
	}
	return err
}

var (
	errUnauthorized = errors.New("unauthorized")
	errForbidden    = errors.New("forbidden")
)

func (c *ghpClient) do(ctx context.Context, method, path string, payload, out interface{}) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling ghp %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusNotFound:
		return errNotFound
	case http.StatusUnauthorized:
		return errUnauthorized
	case http.StatusForbidden:
		return errForbidden
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ghp %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decoding ghp response: %w", err)
	}
	return nil
}
