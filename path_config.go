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
	AwsAccessKeyId     string `json:"aws_access_key_id"`
	AwsSecretAccessKey string `json:"aws_secret_access_key"`
	AwsSessionToken    string `json:"aws_session_token"`
}

func pathConfig(b *cognitoSecretBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"aws_access_key_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The AWS access key for accessing the AWS API (Optional).`,
			},
			"aws_secret_access_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The AWS secret  access key for accessing the AWS API (Optional).`,
			},
			"aws_session_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `The AWS session token for accessing the AWS API (Optional).`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
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

	if awsAccessKeyId, ok := data.GetOk("aws_access_key_id"); ok {
		config.AwsAccessKeyId = awsAccessKeyId.(string)
	}

	if awsSecretAccessKey, ok := data.GetOk("aws_secret_access_key"); ok {
		config.AwsSecretAccessKey = awsSecretAccessKey.(string)
	}

	if awsSessionToken, ok := data.GetOk("aws_session_token"); ok {
		config.AwsSessionToken = awsSessionToken.(string)
	}

	if merr.ErrorOrNil() != nil {
		return logical.ErrorResponse(merr.Error()), nil
	}

	err = b.saveConfig(ctx, config, req.Storage)

	return nil, err
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
The Cognito secret backend requires AWS credentials for managing users in the a user pool.
`
