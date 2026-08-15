package ghp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, url, token string) *ghpClient {
	t.Helper()
	c, err := newClient(&ghpConfig{BaseURL: url, AdminToken: token})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return c
}

func TestClientCreateAndRevokeToken(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	c := testClient(t, srv.URL, "ghpsvc_seed")
	ctx := context.Background()

	out, err := c.CreateToken(ctx, createTokenRequest{
		Type: tokenTypeAgent, InstallationID: 42, Scopes: "contents:read", SessionID: "vault-x",
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if out.Token == "" || out.ID == "" {
		t.Fatalf("CreateToken returned empty value/id: %#v", out)
	}
	if !fake.has(out.ID) {
		t.Fatal("token not stored in fake")
	}

	if err := c.RevokeToken(ctx, out.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if fake.has(out.ID) {
		t.Fatal("token still present after revoke")
	}

	// Revoking a non-existent token (404) is treated as success.
	if err := c.RevokeToken(ctx, "tok-999999"); err != nil {
		t.Fatalf("RevokeToken of missing token should succeed, got: %v", err)
	}
}

func TestClientUnauthorized(t *testing.T) {
	fake := newFakeGHP("ghpsvc_correct")
	srv := fake.server(t)
	defer srv.Close()

	c := testClient(t, srv.URL, "ghpsvc_wrong")
	_, err := c.CreateToken(context.Background(), createTokenRequest{Type: tokenTypeAgent, InstallationID: 1})
	if err == nil {
		t.Fatal("expected unauthorized error with wrong token")
	}
}

func TestClientVerifyAdmin(t *testing.T) {
	fake := newFakeGHP("ghpsvc_seed")
	srv := fake.server(t)
	defer srv.Close()

	if err := testClient(t, srv.URL, "ghpsvc_seed").VerifyAdmin(context.Background()); err != nil {
		t.Fatalf("VerifyAdmin with valid admin token: %v", err)
	}

	// Invalid token → 401 → clear message.
	err := testClient(t, srv.URL, "nope").VerifyAdmin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not a configured service token") {
		t.Errorf("expected 401 message, got: %v", err)
	}
}

func TestClientVerifyAdminNonAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := testClient(t, srv.URL, "ghpsvc_seed").VerifyAdmin(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not a ghp admin") {
		t.Errorf("expected non-admin error, got: %v", err)
	}
}

func TestClientRequiresConfig(t *testing.T) {
	if _, err := newClient(&ghpConfig{BaseURL: "https://ghp.example.com"}); err == nil {
		t.Fatal("expected error when admin_token missing")
	}
	if _, err := newClient(&ghpConfig{AdminToken: "t"}); err == nil {
		t.Fatal("expected error when base_url missing")
	}
	if _, err := newClient(&ghpConfig{BaseURL: "x", AdminToken: "t", CACert: "not-a-pem"}); err == nil {
		t.Fatal("expected error for invalid ca_cert")
	}
}
