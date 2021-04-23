package cognito

import (
	"context"
	"errors"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
)

// cognitoConfig contains values to configure cognito clients and
// defaults for roles. The zero value is useful and results in
// environments variable and system defaults being used.
type cognitoConfig struct {
	CognitoPoolUrl  string `json:"cognito_pool_url"`
	AppClientSecret string `json:"app_client_secret"`
}

func pathConfig(b *cognitoSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"cognito_pool_url": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The cognito pool url.
				This value can also be provided with the COGNITO_POOL_URL environment variable.`,
			},
			"app_client_secret": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The app client secret for the Cognito User Pool. This value can also
				be provided with the APP_CLIENT_SECRET environment variable.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigRead,
			logical.CreateOperation: b.pathConfigWrite,
			logical.UpdateOperation: b.pathConfigWrite,
			logical.DeleteOperation: b.pathConfigDelete,
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    confHelpSyn,
		HelpDescription: confHelpDesc,
	}
}

func (b *cognitoSecretBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var merr *multierror.Error

	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config not found during update operation")
		}
		config = new(cognitoConfig)
	}

	if cognitoPoolUrl, ok := data.GetOk("cognito_pool_url"); ok {
		config.CognitoPoolUrl = cognitoPoolUrl.(string)
	}

	if appClientSecret, ok := data.GetOk("app_client_secret"); ok {
		config.AppClientSecret = appClientSecret.(string)
	}

	if merr.ErrorOrNil() != nil {
		return logical.ErrorResponse(merr.Error()), nil
	}

	err = b.saveConfig(ctx, config, req.Storage)

	return nil, err
}

func (b *cognitoSecretBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)

	if err != nil {
		return nil, err
	}

	if config == nil {
		config = new(cognitoConfig)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"cognito_pool_url":  config.CognitoPoolUrl,
			"app_client_secret": config.AppClientSecret,
		},
	}
	return resp, nil
}

func (b *cognitoSecretBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func (b *cognitoSecretBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return config != nil, err
}

func (b *cognitoSecretBackend) getConfig(ctx context.Context, s logical.Storage) (*cognitoConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(cognitoConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	return config, nil
}

func (b *cognitoSecretBackend) saveConfig(ctx context.Context, config *cognitoConfig, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)

	if err != nil {
		return err
	}

	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}

	// reset the backend since the client and provider will have been
	// built using old versions of this data
	b.reset()

	return nil
}

const confHelpSyn = `Configure the Cognito Secret backend.`
const confHelpDesc = `
The Cognito secret backend requires credentials for managing applications and
service principals. This endpoint is used to configure those credentials as
well as default values for the backend in general.
`
