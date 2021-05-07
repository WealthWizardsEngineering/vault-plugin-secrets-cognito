package cognito

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAccessToken(b *cognitoSecretBackend) *framework.Path {
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
				Callback:                    b.pathAccessTokenRead,
				ForwardPerformanceSecondary: true,
				ForwardPerformanceStandby:   true,
			},
		},

		HelpSynopsis:    pathAccessTokenHelpSyn,
		HelpDescription: pathAccessTokenHelpDesc,
	}
}

// pathAccessTokenRead generates cognito access token based on the role credential type.
func (b *cognitoSecretBackend) pathAccessTokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("role").(string)

	role, err := getRole(ctx, roleName, req.Storage)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' does not exist", roleName)), nil
	}

	if role.CredentialType == credentialTypeUser {
		return logical.ErrorResponse("Not implemented"), nil
	} else {
		client, _ := b.getClient()
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

func (b *cognitoSecretBackend) spRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := &logical.Response{Secret: req.Secret}

	return resp, nil
}

func (b *cognitoSecretBackend) spRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := new(logical.Response)

	return resp, nil
}

func (b *cognitoSecretBackend) staticSPRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := new(logical.Response)

	return resp, nil
}

const pathAccessTokenHelpSyn = `
Request Service Principal credentials for a given Vault role.
`

const pathAccessTokenHelpDesc = `
This path creates or updates dynamic Service Principal credentials.
The associated role can be configured to create a new App/Service Principal,
or add a new password to an existing App. The Service Principal or password
will be automatically deleted when the lease has expired.
`
