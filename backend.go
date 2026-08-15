// Package ghp implements a Vault / OpenBao secrets engine that mints ephemeral,
// scoped ghp access tokens on demand.
//
// ghp (the GitHub proxy) issues short-lived tokens that front GitHub App
// installations. Machine callers (CI identities, agents, ...) should never hold
// standing ghp tokens. The engine is seeded with a single ghp *service token*
// (ghpsvc_...) that ghp treats as a synthetic site admin, and on each read of
// creds/<role> it calls ghp's admin token API (POST /api/tokens) to mint a fresh
// scoped token for the role. Each minted token is bound to a Vault lease and
// revoked from ghp (DELETE /api/tokens/{id}) when the lease expires or is revoked.
//
// Why a static service token and not a rotated root credential: ghp service
// tokens are configured out-of-band on the ghp server (auth.service_tokens /
// GHP_AUTH_SERVICE_TOKENS) and authenticate as a synthetic admin with no
// database row. There is nothing for the engine to rotate in place, so unlike
// the sibling gitea engine this backend deliberately has no config/rotate-root
// path; the service token is supplied and rotated by Vault/operator config.
//
// Unlike Gitea, ghp tokens *do* expire server-side: each mint sets a duration so
// the token self-expires around the lease ceiling as defence in depth, while the
// Vault lease remains the primary expiry — lease revocation deletes the token.
package ghp

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// errBackendNotConfigured is returned when a credential is requested before the
// ghp connection has been configured.
var errBackendNotConfigured = errors.New("ghp backend not configured; write config first")

type ghpBackend struct {
	*framework.Backend
}

// Factory returns a configured ghp secrets backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *ghpBackend {
	b := &ghpBackend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{configStoragePath},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathRole(b),
				pathRolesList(b),
				pathCredentials(b),
			},
		),
		Secrets: []*framework.Secret{
			b.ghpTokenSecret(),
		},
	}

	return b
}

// clientFor builds a ghp client from the stored config, authenticated with the
// seeded service token.
func (b *ghpBackend) clientFor(ctx context.Context, s logical.Storage) (*ghpClient, error) {
	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errBackendNotConfigured
	}
	return newClient(config)
}

const backendHelp = `
The ghp secrets engine mints ephemeral, scoped ghp access tokens.

Seed the engine with a ghp service token (ghpsvc_...) that ghp accepts as a
synthetic site admin. Roles bind a ghp App installation and a set of GitHub App
permission scopes to TTLs; each read of creds/<role> mints a fresh token via
POST /api/tokens, bound to a Vault lease and deleted from ghp (DELETE
/api/tokens/{id}) on revocation. ghp tokens expire server-side too, so each mint
sets a duration bounded by the lease ceiling.

There is no config/rotate-root: the ghp service token is a static credential
managed on the ghp server and supplied through Vault config, not rotated by this
engine.
`
