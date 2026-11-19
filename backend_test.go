package ghp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// fakeGHP is an in-memory stand-in for the subset of ghp's admin API the plugin
// uses: admin check (GET /api/users), token create (POST /api/tokens) and token
// revoke (DELETE /api/tokens/{id}). Bearer auth is validated against the seeded
// service token, and non-admin behaviour can be simulated by rejecting it.
type fakeGHP struct {
	mu        sync.Mutex
	adminTok  string
	nextID    int64
	tokens    map[string]createdToken // key: id
	minted    int
	forbidden bool // when true, a valid token is treated as non-admin (403)
}

type createdToken struct {
	id           string
	tokenType    string
	repositories []string
	scopes       map[string]string
	sessionID    string
}

func newFakeGHP(adminTok string) *fakeGHP {
	return &fakeGHP{adminTok: adminTok, tokens: map[string]createdToken{}}
}

func (f *fakeGHP) authOK(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	return ok && tok == f.adminTok
}

func (f *fakeGHP) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !f.authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		forbidden := f.forbidden
		f.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/users":
			if forbidden {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeJSON(w, http.StatusOK, []map[string]interface{}{{"id": "svc-admin"}})

		case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
			var in createTokenRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			scopes := map[string]string{}
			if in.Scopes != "" {
				for _, part := range strings.Split(in.Scopes, ",") {
					kv := strings.SplitN(part, ":", 2)
					if len(kv) == 2 {
						scopes[kv[0]] = kv[1]
					}
				}
			}
			f.mu.Lock()
			f.nextID++
			id := "tok-" + strconv.FormatInt(f.nextID, 10)
			f.minted++
			tt := in.Type
			if tt == "" {
				tt = tokenTypeProxy
			}
			f.tokens[id] = createdToken{id: id, tokenType: tt, repositories: in.Repositories, scopes: scopes, sessionID: in.SessionID}
			f.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]interface{}{
				"token":        "gha_" + id,
				"id":           id,
				"type":         tt,
				"repositories": in.Repositories,
				"scopes":       scopes,
				"expires_at":   "2030-01-01T00:00:00Z",
				"session_id":   in.SessionID,
			})

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/tokens/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
			f.mu.Lock()
			_, exists := f.tokens[id]
			delete(f.tokens, id)
			f.mu.Unlock()
			if !exists {
				writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"message": "Token revoked"})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func (f *fakeGHP) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tokens[id]
	return ok
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestBackend(t *testing.T) (*ghpBackend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return b.(*ghpBackend), config.StorageView
}

func req(t *testing.T, b *ghpBackend, s logical.Storage, op logical.Operation, path string, data map[string]interface{}) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("%s %s: %v", op, path, resp.Error())
	}
	return resp
}

func configure(t *testing.T, b *ghpBackend, s logical.Storage, url, token string) {
	t.Helper()
	req(t, b, s, logical.CreateOperation, "config", map[string]interface{}{
		"base_url":    url,
		"admin_token": token,
	})
}

func TestLifecycle(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")

	req(t, b, s, logical.CreateOperation, "roles/agent", map[string]interface{}{
		"token_type":      "agent",
		"installation_id": 4242,
		"scopes":          "contents:read,pull_requests:write",
		"repositories":    "example/app,example/tools",
		"ttl":             "1h",
		"max_ttl":         "24h",
	})

	creds := req(t, b, s, logical.ReadOperation, "creds/agent", nil)
	if creds.Secret == nil {
		t.Fatal("creds returned no secret")
	}
	tokenID, _ := creds.Data["token_id"].(string)
	tokenVal, _ := creds.Data["token"].(string)
	if tokenID == "" || tokenVal == "" {
		t.Fatalf("creds missing token/token_id: %#v", creds.Data)
	}
	if !strings.HasPrefix(tokenVal, "gha_") {
		t.Errorf("token = %q, want gha_ prefix", tokenVal)
	}
	if creds.Data["token_type"].(string) != "agent" {
		t.Errorf("token_type = %q, want agent", creds.Data["token_type"])
	}
	if creds.Data["base_url"].(string) != srv.URL {
		t.Errorf("base_url = %q, want %q", creds.Data["base_url"], srv.URL)
	}
	if !fake.has(tokenID) {
		t.Error("minted token not present in ghp")
	}

	// Renew keeps the same secret.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    creds.Secret,
		Storage:   s,
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// Revoke deletes the token from ghp.
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    creds.Secret,
		Storage:   s,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if fake.has(tokenID) {
		t.Error("token still present after revoke")
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")
	req(t, b, s, logical.CreateOperation, "roles/agent", map[string]interface{}{
		"token_type": "agent", "installation_id": 7,
	})
	creds := req(t, b, s, logical.ReadOperation, "creds/agent", nil)

	revoke := func() error {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.RevokeOperation,
			Secret:    creds.Secret,
			Storage:   s,
		})
		return err
	}
	if err := revoke(); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	// A second revoke (token already gone → 404) must still succeed.
	if err := revoke(); err != nil {
		t.Fatalf("second revoke should be idempotent, got: %v", err)
	}
}

func TestAgentRoleRequiresInstallationID(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Data:      map[string]interface{}{"token_type": "agent"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for agent role without installation_id")
	}
}

func TestScopeValidationOnRole(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")

	// Bad level rejected.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Data:      map[string]interface{}{"token_type": "agent", "installation_id": 1, "scopes": "contents:admin"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for invalid scope level")
	}

	// Valid scopes normalise (level lower-cased, duplicates dropped) and read back.
	req(t, b, s, logical.CreateOperation, "roles/ok", map[string]interface{}{
		"token_type": "agent", "installation_id": 1,
		"scopes": " contents:Read , contents:read, pull_requests:write",
	})
	role := req(t, b, s, logical.ReadOperation, "roles/ok", nil)
	got, _ := role.Data["scopes"].([]string)
	if len(got) != 2 || got[0] != "contents:read" || got[1] != "pull_requests:write" {
		t.Errorf("normalised scopes = %v, want [contents:read pull_requests:write]", got)
	}
}

func TestProxyRoleAllowedWithoutInstallation(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")

	req(t, b, s, logical.CreateOperation, "roles/proxy", map[string]interface{}{
		"token_type": "proxy", "repositories": "example/app",
	})
	creds := req(t, b, s, logical.ReadOperation, "creds/proxy", nil)
	if creds.Secret == nil {
		t.Fatal("proxy mint returned no secret")
	}
	if creds.Data["token_type"].(string) != "proxy" {
		t.Errorf("token_type = %q, want proxy", creds.Data["token_type"])
	}
}

func TestConfigRequiresTokenAndVerifies(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)

	// Missing admin_token.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"base_url": srv.URL},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when admin_token missing")
	}

	// Wrong token fails verification against the fake (401).
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"base_url": srv.URL, "admin_token": "wrong"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when admin_token fails verification")
	}

	// config read must never leak the token.
	configure(t, b, s, srv.URL, "ghpsvc_seed")
	read := req(t, b, s, logical.ReadOperation, "config", nil)
	if _, leaked := read.Data["admin_token"]; leaked {
		t.Fatal("config read leaked admin_token")
	}
	if read.Data["base_url"].(string) != srv.URL {
		t.Errorf("base_url = %q, want %q", read.Data["base_url"], srv.URL)
	}
}

func TestConfigRequiresBaseURL(t *testing.T) {
	b, s := newTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"admin_token": "ghpsvc_seed"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when base_url missing")
	}
	if !strings.Contains(resp.Error().Error(), "base_url is required") {
		t.Errorf("unexpected error: %v", resp.Error())
	}
}

func TestConfigRejectsNonAdminToken(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	fake.forbidden = true
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Data:      map[string]interface{}{"base_url": srv.URL, "admin_token": "ghpsvc_seed"},
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when token authenticates but is not admin")
	}
	if !strings.Contains(resp.Error().Error(), "not a ghp admin") {
		t.Errorf("unexpected error: %v", resp.Error())
	}
}

func TestCredsBeforeConfig(t *testing.T) {
	b, s := newTestBackend(t)
	req(t, b, s, logical.CreateOperation, "roles/x", map[string]interface{}{
		"token_type": "agent", "installation_id": 1,
	})
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/x",
		Storage:   s,
	})
	if err == nil {
		t.Fatal("expected creds read to fail without config")
	}
}

func TestRolesList(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	b, s := newTestBackend(t)
	configure(t, b, s, srv.URL, "ghpsvc_seed")
	req(t, b, s, logical.CreateOperation, "roles/a", map[string]interface{}{"token_type": "agent", "installation_id": 1})
	req(t, b, s, logical.CreateOperation, "roles/b", map[string]interface{}{"token_type": "agent", "installation_id": 2})

	list := req(t, b, s, logical.ListOperation, "roles/", nil)
	keys, _ := list.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Fatalf("roles list = %v, want 2 entries", keys)
	}
}
