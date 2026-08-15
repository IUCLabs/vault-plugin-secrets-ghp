package ghp

import (
	"strings"
	"testing"
)

func TestNormalizeScopes(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"single", []string{"contents:read"}, []string{"contents:read"}, false},
		{"trim+level-case", []string{" pull_requests:Write "}, []string{"pull_requests:write"}, false},
		{"dedupe-identical", []string{"contents:read", "contents:read"}, []string{"contents:read"}, false},
		{"multi", []string{"contents:read", "issues:write"}, []string{"contents:read", "issues:write"}, false},
		{"empty-input", nil, []string{}, false},
		{"blank-entries", []string{"", "  "}, []string{}, false},
		{"no-level", []string{"contents"}, nil, true},
		{"bad-level", []string{"contents:admin"}, nil, true},
		{"empty-perm", []string{":read"}, nil, true},
		{"conflict", []string{"contents:read", "contents:write"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeScopes(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("normalizeScopes(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestScopeString(t *testing.T) {
	if got := scopeString(nil); got != "" {
		t.Errorf("scopeString(nil) = %q, want empty", got)
	}
	if got := scopeString([]string{"contents:read", "issues:write"}); got != "contents:read,issues:write" {
		t.Errorf("scopeString = %q", got)
	}
}
