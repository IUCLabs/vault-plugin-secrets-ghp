// Command mockghp is an in-memory stand-in for the subset of the ghp admin API
// that vault-plugin-secrets-ghp uses: admin check (GET /api/users), token
// create (POST /api/tokens) and token revoke (DELETE /api/tokens/{id}). It is
// used by the e2e tests — no real ghp, database, or GitHub App required. Not for
// production use.
//
// Authentication is a bearer service token (MOCKGHP_ADMIN_TOKEN) matched exactly;
// a valid token is treated as a synthetic admin, exactly as real ghp treats its
// configured service tokens.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

type createTokenRequest struct {
	Type           string   `json:"type"`
	AppRecordID    string   `json:"app_record_id"`
	Repositories   []string `json:"repositories"`
	InstallationID int64    `json:"installation_id"`
	Scopes         string   `json:"scopes"`
	Duration       string   `json:"duration"`
	SessionID      string   `json:"session_id"`
}

type store struct {
	mu       sync.Mutex
	adminTok string
	nextID   int64
	tokens   map[string]bool // key: id
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func (s *store) authOK(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	return ok && tok == s.adminTok
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *store) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, []map[string]interface{}{{"id": "svc-admin", "role": "admin"}})
}

func (s *store) handleTokens(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/tokens":
		var in createTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tt := in.Type
		if tt == "" {
			tt = "proxy"
		}
		s.mu.Lock()
		s.nextID++
		id := "tok-" + strconv.FormatInt(s.nextID, 10)
		s.tokens[id] = true
		s.mu.Unlock()
		scopes := map[string]string{}
		for _, part := range strings.Split(in.Scopes, ",") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				scopes[kv[0]] = kv[1]
			}
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"token":        "gha_" + randHex(16),
			"id":           id,
			"type":         tt,
			"repositories": in.Repositories,
			"scopes":       scopes,
			"expires_at":   "2030-01-01T00:00:00Z",
			"session_id":   in.SessionID,
		})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/tokens/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
		s.mu.Lock()
		exists := s.tokens[id]
		delete(s.tokens, id)
		s.mu.Unlock()
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "Token revoked"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func main() {
	addr := os.Getenv("MOCKGHP_ADDR")
	if addr == "" {
		addr = ":3000"
	}
	adminTok := os.Getenv("MOCKGHP_ADMIN_TOKEN")
	if adminTok == "" {
		adminTok = "ghpsvc_seed"
	}
	s := &store{adminTok: adminTok, tokens: map[string]bool{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/tokens", s.handleTokens)
	mux.HandleFunc("/api/tokens/", s.handleTokens)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	log.Printf("mock ghp API listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux)) //nolint:gosec // test-only mock
}
