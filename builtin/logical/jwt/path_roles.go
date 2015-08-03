package jwt

import (
	"fmt"
	"errors"
	"strings"
	"time"

	"github.com/fatih/structs"
	jwt "github.com/dgrijalva/jwt-go"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `roles/(?P<name>\w+)`,
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the Role",
			},
			"algorithm": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "RS256",
				Description: "Algorithm for JWT Signing",
			},
			"key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Private Key (RSA or EC) or String for HMAC Algorithm",
			},
			"lease": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Use leases, if true, tokens will be kept for 30 days, if false, tokens and claims are not stored",
			},
			"iss": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Default Issuer for the Role for the JWT Tokens",
			},
			"sub": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Default Subject for the Role for the JWT Token",
			},
			"aud": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Default Audience for the Role for the JWT Token",
			},
			"exp": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "0h",
				Description: "Default Expiration (from time of issue) for the Role fpr the JWT Token, expressed in Duration, Example: 24h",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.WriteOperation:  b.pathRoleCreate,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) getRole(s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get("role/" + n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete("role/" + data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	var r = structs.New(role).Map()

	delete(r, "key")

	resp := &logical.Response{
		Data: r,
	}

	return resp, nil
}

func (b *backend) pathRoleCreate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	key  := data.Get("key").(string)
	alg  := data.Get("algorithm").(string)
	expRaw  := data.Get("exp").(string)
	
	signingMethod := jwt.GetSigningMethod(data.Get("algorithm").(string))
	if signingMethod == nil {
		return nil, errors.New("Invalid Signing Algorithm")
	}

	if key == "" {
		return nil, errors.New("Key is Required")
	}

	if strings.HasPrefix(alg, "RS") {
		// need RSA Private Key
		if strings.Contains(key, "RSA PRIVATE KEY") == false {
			return nil, errors.New("Key is not a PEM formatted RSA Private Key")
		}
	} else if strings.HasPrefix(alg, "HS") {
		// need a string
		if key == "" {
			return nil, errors.New("Key must not be blank")
		}
	} else if strings.HasPrefix(alg, "EC") {
		// need EC Private Key
		if strings.Contains(key, "EC PRIVATE KEY") == false {
			return nil, errors.New("Key is not a PEM formatted EC Private Key")
		}
	}

	exp, err := time.ParseDuration(expRaw)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Invalid Default Expiration: %s", err)), nil
	}

	entry := &roleEntry{
		Algorithm:    alg,
		Key:          key,
		Lease:        data.Get("lease").(bool),
		Issuer:       data.Get("iss").(string),
		Subject:      data.Get("sub").(string),
		Audience:     data.Get("aud").(string),
		Expiration:   exp,
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/" + name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleEntry struct {
	Algorithm      string        `json:"algorithm" structs:"algorithm" mapstructure:"algorithm"`
	Key            string        `json:"key" structs:"key" mapstructure:"key"`
	Lease          bool          `json:"lease" structs:"lease" mapstructure:"lease"`
	Issuer         string        `json:"iss" structs:"iss" mapstructure:"iss"`
	Subject        string        `json:"sub" structs:"sub" mapstructure:"sub"`
	Audience       string        `json:"aud" structs:"aud" mapstructure:"aud"`
	Expiration     time.Duration `json:"exp" structs:"exp" mapstructure:"exp"`
}

const pathRolesHelpSyn = `
Read and write basic configuration for generating signed JWT Tokens.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create JWT tokens. These roles have a few settings that dictated
what signing algorithm is used for the JWT token. For example,
if the backend is mounted at "jwt" and you create a role at
"jwt/roles/auth" then a user can request a JWT token at "jwt/issue/auth".
`
