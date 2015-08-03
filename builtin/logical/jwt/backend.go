package jwt

import (
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory creates a new backend implementing the logical.Backend interface
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend().Setup(conf)
}

// Backend returns a new Backend framework struct
func Backend() *framework.Backend {
	var b backend
	b.Backend = &framework.Backend{

		Paths: []*framework.Path{
			pathRoles(&b),
			pathIssue(&b),
			pathTokens(&b),
		},

		Secrets: []*framework.Secret{
			secretTokens(&b),
		},

	}

	return b.Backend
}

type backend struct {
	*framework.Backend
}

type roleConfig struct {
	Algorithm string        `json:"algorithm" structs:"algorithm" mapstructure:"algorithm"`
	Key       string        `json:"key" structs:"key" mapstructure:"key"`
}

type configLease struct {
	Lease     time.Duration
	LeaseMax  time.Duration
}
