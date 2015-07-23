package jwt

import (
	"fmt"
	"time"
	"encoding/json"

	jwt "github.com/dgrijalva/jwt-go"

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
			"jit": &framework.FieldSchema{
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

	token := jwt.New(jwt.SigningMethodRS256)

	if data.Get("claims").(string) != "" {
		// Parse JSON using unmarshal
		var uc map[string]interface{}
		err := json.Unmarshal([]byte(data.Get("claims").(string)), &uc)
		if err != nil {
			return nil, err
		}
		
		for k, v := range uc {
			token.Claims[k] = v
		}
	}

	if _, ok := token.Claims["iss"]; !ok {
		if data.Get("iss") != "" {
			token.Claims["iss"] = data.Get("iss").(string)
		}
	}
	if _, ok := token.Claims["sub"]; !ok {
		if data.Get("sub") != "" {
			token.Claims["sub"] = data.Get("sub").(string)
		}
	}
	if _, ok := token.Claims["aud"]; !ok {
		if data.Get("aud") != "" {
			token.Claims["aud"] = data.Get("aud").(string)
		}
	}
	if _, ok := token.Claims["exp"]; !ok {
		if data.Get("exp").(int) > 0 {
			token.Claims["exp"] = data.Get("exp").(int)
		}
	}
	if _, ok := token.Claims["nbf"]; !ok {
		if data.Get("nbf").(int) > 0 {
			token.Claims["nbf"] = data.Get("nbf").(int)
		}
	}
	if _, ok := token.Claims["iat"]; !ok {
		if data.Get("iat").(int) > 0 {
			token.Claims["iat"] = data.Get("iat").(int)
		}
	}
	if _, ok := token.Claims["jit"]; !ok {
		if data.Get("jit") != "" {
			token.Claims["jit"] = data.Get("jit").(string)
		}
	}

	entry, err := req.Storage.Get("config/" + roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf(
			"License Private Key haven't been configured. Please configure\n" +
				"them at the 'config/" + roleName + "' endpoint")
	}

	var config roleConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading jwt configuration: %s", err)
	}

	tokenString, err := token.SignedString([]byte(config.Key))

	if err != nil {
		return nil, err
	}

	resp := b.Secret(SecretTokensType).Response(map[string]interface{}{
		"jit": token.Claims["jit"].(string),
		"token": tokenString,
	}, map[string]interface{} {
		"jit": data.Get("jit").(string),
	})

	err = req.Storage.Put(&logical.StorageEntry{
		Key:   "tokens/" + data.Get("jit").(string),
		Value: []byte(tokenString),
	})
	if err != nil {
		return nil, fmt.Errorf("Unable to store token locally")
	}

	return resp, nil
}





