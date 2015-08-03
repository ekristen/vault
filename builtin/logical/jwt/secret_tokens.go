package jwt

import (
	"fmt"
	"time"
	"encoding/json"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/hashicorp/vault/logical"
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

		DefaultDuration: 720 * time.Hour,

		Renew:  b.secretTokensRenew,
		Revoke: b.secretTokensRevoke,
	}
}

// Change FieldData for Map/Struct, so it is more versatile.

func (b *backend) secretTokensCreate(
	req *logical.Request, data *framework.FieldData, claims map[string]interface{}, roleName string) (*logical.Response, error) {

	role, err := b.getRole(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("Unknown role: %s", roleName)), nil
	}

	//token := jwt.New(jwt.SigningMethodRS256)
	token := jwt.New(jwt.GetSigningMethod(role.Algorithm))

	token.Claims = claims

	tokenString, err := token.SignedString([]byte(role.Key))

	if err != nil {
		return nil, err
	}

	if role.Lease == true {
		resp := b.Secret(SecretTokensType).Response(map[string]interface{}{
			"role": roleName,
			"jti": claims["jti"].(string),
			"token": tokenString,
		}, map[string]interface{} {
			"role": roleName,
			"jti": claims["jti"].(string),
			"claims": token.Claims,
		})

		resp.Secret.Lease = 720 * time.Hour

		err = req.Storage.Put(&logical.StorageEntry{
			Key:   "tokens/" + claims["jti"].(string),
			Value: []byte(tokenString),
		})
		if err != nil {
			return nil, fmt.Errorf("Unable to store token locally")
		}

		c, err := json.Marshal(token.Claims)
		if (err != nil) {
			return nil, err
		}

		err = req.Storage.Put(&logical.StorageEntry{
			Key:   "claims/" + claims["jti"].(string),
			Value: c,
		})
		if err != nil {
			return nil, fmt.Errorf("Unable to store token claims locally")
		}
		
		return resp, nil
	} else {
		resp := &logical.Response{
			Data: map[string]interface{}{
				"jti": claims["jti"].(string),
				"token": tokenString,
			},
		}
		
		return resp, nil
	}
}

func (b *backend) secretTokensRenew(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role, err := b.getRole(req.Storage, roleName.(string))
	if err != nil {
		return nil, err
	}

	if role.Lease == false {
		return nil, fmt.Errorf("There is nothing to renew")
	}

	claimsRaw, ok := req.Secret.InternalData["claims"]
	claims, ok := claimsRaw.(map[string]interface{})

	lease := &configLease{Lease: 720 * time.Hour}

	f := framework.LeaseExtend(lease.Lease, 0, false)
	resp, err := f(req, d)
	if err != nil {
		return nil, err
	}

	tresp, err := b.secretTokensCreate(req, d, claims, roleName.(string))

	resp.Data = tresp.Data
	
	return resp, nil
}

func (b *backend) secretTokensRevoke(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the username from the internal data
	jtiRaw, ok := req.Secret.InternalData["jti"]
	if !ok {
		return nil, fmt.Errorf("secret is missing jti internal data")
	}
	jti, ok := jtiRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing jti internal data")
	}

	// DELETE TOKEN ENTRY FROM SECRET BACKEND
	err := req.Storage.Delete("tokens/" + jti)
	if err != nil {
		return nil, err
	}

	return nil, nil
}





