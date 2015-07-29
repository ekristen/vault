package jwt

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathTokens(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `tokens/(?P<jti>[0-9A-Fa-f-:]+)`,
		Fields: map[string]*framework.FieldSchema{
			"jti": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "JWT Token Identifier",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathTokenRead,
		},
	}
}

func (b *backend) pathTokenRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get("tokens/" + data.Get("jti").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"token": string(entry.Value),
		},
	}

	return resp, nil
}
