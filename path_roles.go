package cognito

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	rolesStoragePath = "roles"

	credentialTypeClientCredentialsGrant = "client_credentials_grant"
	credentialTypeUser                   = "user"
)

// roleEntry is a Vault role construct that maps to cognito configuration
type roleEntry struct {
	CredentialType    string        `json:"credential_type"`
	CognitoPoolDomain string        `json:"cognito_pool_domain"`
	AppClientSecret   string        `json:"app_client_secret"`
	Region            string        `json:"region"`
	AppClientId       string        `json:"app_client_id"`
	UserPoolId        string        `json:"user_pool_id"`
	Group             string        `json:"group"`
	DummyEmailDomain  string        `json:"dummy_email_domain"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
}

func pathsRole(b *cognitoSecretBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
				},
				"credential_type": {
					Type:        framework.TypeString,
					Description: "credential_type",
				},
				"cognito_pool_domain": {
					Type:        framework.TypeString,
					Description: "cognito_pool_domain",
				},
				"app_client_secret": {
					Type:        framework.TypeString,
					Description: "app_client_secret.",
				},
				"region": {
					Type:        framework.TypeString,
					Description: "region.",
				},
				"app_client_id": {
					Type:        framework.TypeString,
					Description: "app_client_id.",
				},
				"user_pool_id": {
					Type:        framework.TypeString,
					Description: "user_pool_id.",
				},
				"group": {
					Type:        framework.TypeString,
					Description: "group.",
				},
				"dummy_email_domain": {
					Type:        framework.TypeString,
					Description: "dummy_email_domain.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time a service principal. If not set or set to 0, will use system default.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleUpdate,
				logical.UpdateOperation: b.pathRoleUpdate,
				logical.DeleteOperation: b.pathRoleDelete,
			},
			HelpSynopsis:    roleHelpSyn,
			HelpDescription: roleHelpDesc,
			ExistenceCheck:  b.pathRoleExistenceCheck,
		},
		{
			Pattern: "roles/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    roleListHelpSyn,
			HelpDescription: roleListHelpDesc,
		},
	}

}

// pathRoleUpdate creates or updates Vault roles.
//
// Basic validity check are made to verify that the provided fields meet requirements
// for the given credential type.
//
func (b *cognitoSecretBackend) pathRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var resp *logical.Response

	// load or create role
	name := d.Get("name").(string)
	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = &roleEntry{
			CredentialType: credentialTypeClientCredentialsGrant,
		}
	}

	// update and verify credential type if provided
	if credentialType, ok := d.GetOk("credential_type"); ok {
		role.CredentialType = credentialType.(string)
	}

	// update and verify Application Object ID if provided
	if cognitoPoolDomain, ok := d.GetOk("cognito_pool_domain"); ok {
		role.CognitoPoolDomain = cognitoPoolDomain.(string)
	}

	if appClientSecret, ok := d.GetOk("app_client_secret"); ok {
		role.AppClientSecret = appClientSecret.(string)
	}

	if region, ok := d.GetOk("region"); ok {
		role.Region = region.(string)
	}

	if appClientId, ok := d.GetOk("app_client_id"); ok {
		role.AppClientId = appClientId.(string)
	}

	if userPoolId, ok := d.GetOk("user_pool_id"); ok {
		role.UserPoolId = userPoolId.(string)
	}

	if group, ok := d.GetOk("group"); ok {
		role.Group = group.(string)
	}

	if dummyEmailDomain, ok := d.GetOk("dummy_email_domain"); ok {
		role.DummyEmailDomain = dummyEmailDomain.(string)
	}

	// load and validate TTLs
	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.TTL = time.Duration(d.Get("ttl").(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Duration(d.Get("max_ttl").(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// save role
	err = saveRole(ctx, req.Storage, role, name)
	if err != nil {
		return nil, errwrap.Wrapf("error storing role: {{err}}", err)
	}

	return resp, nil
}

func (b *cognitoSecretBackend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var data = make(map[string]interface{})

	name := d.Get("name").(string)

	r, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return nil, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	if r == nil {
		return nil, nil
	}

	data["credential_type"] = r.CredentialType
	if r.CredentialType == credentialTypeUser {
		data["region"] = r.Region
		data["app_client_id"] = r.AppClientId
		data["user_pool_id"] = r.UserPoolId
		data["group"] = r.Group
		data["dummy_email_domain"] = r.DummyEmailDomain
		data["ttl"] = r.TTL / time.Second
		data["max_ttl"] = r.MaxTTL / time.Second
	} else {
		data["cognito_pool_domain"] = r.CognitoPoolDomain
		data["app_client_secret"] = r.AppClientSecret
	}

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *cognitoSecretBackend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath+"/")
	if err != nil {
		return nil, errwrap.Wrapf("error listing roles: {{err}}", err)
	}

	return logical.ListResponse(roles), nil
}

func (b *cognitoSecretBackend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	err := req.Storage.Delete(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, errwrap.Wrapf("error deleting role: {{err}}", err)
	}

	return nil, nil
}

func (b *cognitoSecretBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	role, err := getRole(ctx, name, req.Storage)
	if err != nil {
		return false, errwrap.Wrapf("error reading role: {{err}}", err)
	}

	return role != nil, nil
}

func saveRole(ctx context.Context, s logical.Storage, c *roleEntry, name string) error {
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", rolesStoragePath, name), c)
	if err != nil {
		return err
	}

	return s.Put(ctx, entry)
}

func getRole(ctx context.Context, name string, s logical.Storage) (*roleEntry, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("%s/%s", rolesStoragePath, name))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	role := new(roleEntry)
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

const roleHelpSyn = "Manage the Vault roles used to generate cognito credentials."
const roleHelpDesc = `
This path allows you to read and write roles that are used to generate cognito login
credentials.

If the backend is mounted at "cognito", you would create a Vault role at "cognito/roles/my_role",
and request credentials from "cognito/creds/my_role".
`
const roleListHelpSyn = `List existing roles.`
const roleListHelpDesc = `List existing roles by name.`
