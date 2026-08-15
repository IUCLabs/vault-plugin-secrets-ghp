package ghp

import (
	"fmt"
	"strings"
)

// normalizeScopes validates ghp scope entries of the form "permission:level"
// (matching ghp's token.ParseScopeString), where level is read or write and
// permission is a GitHub App permission key. It trims, lower-cases the level,
// de-duplicates identical entries and rejects a permission requested at two
// different levels. Order is preserved (first occurrence wins). An empty input
// is valid and yields no scopes: ghp treats an open-scoped token as all-repos.
func normalizeScopes(scopes []string) ([]string, error) {
	seen := make(map[string]string, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		kv := strings.SplitN(s, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid scope %q; expected permission:level (e.g. contents:read)", raw)
		}
		perm := strings.TrimSpace(kv[0])
		level := strings.ToLower(strings.TrimSpace(kv[1]))
		if perm == "" {
			return nil, fmt.Errorf("invalid scope %q; permission must not be empty", raw)
		}
		if level != "read" && level != "write" {
			return nil, fmt.Errorf("invalid scope level %q in %q; must be read or write", kv[1], raw)
		}
		if prev, ok := seen[perm]; ok {
			if prev != level {
				return nil, fmt.Errorf("permission %q requested at conflicting levels %q and %q", perm, prev, level)
			}
			continue
		}
		seen[perm] = level
		out = append(out, perm+":"+level)
	}
	return out, nil
}

// scopeString joins normalized scopes into the comma-separated form ghp's
// POST /api/tokens expects; an empty slice yields an empty (open-scoped) string.
func scopeString(scopes []string) string {
	return strings.Join(scopes, ",")
}
