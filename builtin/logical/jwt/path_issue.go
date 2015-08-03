package jwt

import (
	"fmt"
	"time"
	"encoding/json"

	"github.com/hashicorp/vault/helper/uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `issue/(?P<role>\w[\w-]+\w)`,
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "The desired role with configuration for this request",
			},
			"iss": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The issuer of the token",
			},
			"sub": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The subject of the token",
			},
			"aud": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The audience of the token",
			},
			"exp": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Default:     int(0),
				Description: "This will define the expiration in NumericDate value",
			},
			"nbf": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Default:     int(time.Now().Unix()),
				Description: "Defines the time before which the JWT MUST NOT be accepted for processing",
			},
			"iat": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Default:     int(time.Now().Unix()),
				Description: "The time the JWT was issued",
			},
			"jti": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     uuid.GenerateUUID(),
				Description: "Unique identifier for the JWT",
			},
			"claims": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "JSON Object of Claims for the JWT Token",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.WriteOperation: b.pathIssueWrite,
		},
	}
}

func (b *backend) pathIssueWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	
	// Get the role
	role, err := b.getRole(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("Unknown role: %s", roleName)), nil
	}

	claims := map[string]interface{}{
		"initial": "ok",
	}

	if role.Issuer != "" {
		claims["iss"] = role.Issuer
	}
	if role.Subject != "" {
		claims["sub"] = role.Subject
	}
	if role.Audience != "" {
		claims["aud"] = role.Audience
	}
	if role.Expiration != 0 {
		claims["exp"] = int(time.Now().Add(role.Expiration).Unix())
	}

	if data.Get("iss") != "" {
		claims["iss"] = data.Get("iss").(string)
	}
	if data.Get("sub") != "" {
		claims["sub"] = data.Get("sub").(string)
	}
	if data.Get("aud") != "" {
		claims["aud"] = data.Get("aud").(string)
	}
	if data.Get("exp").(int) > 0 {
		claims["exp"] = data.Get("exp").(int)
	}
	if data.Get("nbf").(int) > 0 {
		claims["nbf"] = data.Get("nbf").(int)
	}
	if data.Get("iat").(int) > 0 {
		claims["iat"] = data.Get("iat").(int)
	}
	if data.Get("jti") != "" {
		claims["jti"] = data.Get("jti").(string)
	}

	if data.Get("claims").(string) != "" {
		// Parse JSON using unmarshal
		var uc map[string]interface{}
		err := json.Unmarshal([]byte(data.Get("claims").(string)), &uc)
		if err != nil {
			return nil, err
		}
		
		for k, v := range uc {
			claims[k] = v
		}
	}

	delete(claims, "initial")

	return b.secretTokensCreate(req, data, claims, roleName)
}
