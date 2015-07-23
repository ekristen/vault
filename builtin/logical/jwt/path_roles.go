package jwt

import (
	"errors"

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

	resp := &logical.Response{
		Data: structs.New(role).Map(),
	}

	return resp, nil
}

func (b *backend) pathRoleCreate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	signingMethod := jwt.GetSigningMethod(data.Get("algorithm").(string))
	if signingMethod == nil {
		return nil, errors.New("Invalid Signing Algorithm")
	}

	entry := &roleEntry{
		Algorithm:    data.Get("algorithm").(string),
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleEntry struct {
	Algorithm             string `json:"algorithm" structs:"algorithm" mapstructure:"algorithm"`
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

