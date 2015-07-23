package jwt

import (
	"fmt"
	"strings"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `roles/(?P<name>\w+)/config`,
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Role",
			},
			"key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The private key or string that signs the license key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.WriteOperation: b.pathConfigWrite,
		},
	}
}

func (b *backend) pathConfigWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	// Get the role
	role, err := b.getRole(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("Unknown role: %s", roleName)), nil
	}

	if strings.HasPrefix(role.Algorithm, "RS") {
		// need RSA Private Key
		if strings.Contains(data.Get("key").(string), "RSA PRIVATE KEY") == false {
			return nil, errors.New("Key is not a PEM formatted RSA Private Key")
		}
	} else if strings.HasPrefix(role.Algorithm, "HS") {
		// need a string
		if data.Get("key").(string) == "" {
			return nil, errors.New("Key must not be blank")
		}
	} else if strings.HasPrefix(role.Algorithm, "EC") {
		// need EC Private Key
		if strings.Contains(data.Get("key").(string), "EC PRIVATE KEY") == false {
			return nil, errors.New("Key is not a PEM formatted EC Private Key")
		}
	}

	entry, err := logical.StorageEntryJSON("config/" + data.Get("name").(string), config{
		Key: string(data.Get("key").(string)),
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

type config struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type roleConfig struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}





