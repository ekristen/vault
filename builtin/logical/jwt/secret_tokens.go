package jwt

import (
	"github.com/hashicorp/vault/logical/framework"
)

// SecretCertsType is the name used to identify this type
const SecretTokensType = "token"

func secretTokens(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTokensType,
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "The Signed JWT Token",
			},
		},
	}
}

