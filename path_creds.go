package cognito

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretTypeUser = "user"
)

func secretUser(b *cognitoSecretBackend) *framework.Secret {
	return &framework.Secret{
		Type:   SecretTypeUser,
		Renew:  b.userRenew,
		Revoke: b.userRevoke,
	}
}

func pathCreds(b *cognitoSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("creds/%s", framework.GenericNameRegex("role")),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the Vault role",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathCredsRead,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},

		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

// pathCredsRead generates cognito access token based on the role credential type.
func (b *cognitoSecretBackend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("role").(string)

	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}

	client, _ := b.getClient()
	if role.CredentialType == credentialTypeUser {
		rawData, err := client.getNewUser(role.Region, role.ClientId, role.UserPoolId, role.Group, role.DummyEmailDomain)
		if err != nil {
			return nil, err
		}

		internalData := map[string]interface{}{
			"username": rawData["username"],
			"role":     roleName,
		}
		return b.Secret(SecretTypeUser).Response(rawData, internalData), nil
	} else {
		rawData, err := client.getAccessToken(role.CognitoPoolUrl, role.AppClientSecret)
		if err != nil {
			return nil, err
		}
		// Generate the response
		resp := &logical.Response{
			Data: rawData,
		}
		return resp, nil
	}
}

func (b *cognitoSecretBackend) userRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}

	return resp, nil
}

func (b *cognitoSecretBackend) userRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := new(logical.Response)

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, errors.New("internal data 'username' not found")
	}

	username := usernameRaw.(string)
	b.Logger().Info(fmt.Sprintf("Revoke lease for User: %s", username))

	c, err := b.getClient()
	if err != nil {
		return nil, errwrap.Wrapf("error during revoke: {{err}}", err)
	}

	err = c.deleteUser(username)

	return resp, err
}

const pathCredsHelpSyn = `
Request Service Principal credentials for a given Vault role.
`

const pathCredsHelpDesc = `
This path creates or updates dynamic Service Principal credentials.
The associated role can be configured to create a new App/Service Principal,
or add a new password to an existing App. The Service Principal or password
will be automatically deleted when the lease has expired.
`
