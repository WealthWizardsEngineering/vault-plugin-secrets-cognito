package cognito

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type cognitoSecretBackend struct {
	*framework.Backend

	getClient func() (client, error)
	lock      sync.RWMutex
}

var _ logical.Factory = Factory

// Factory configures and returns Cognito backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*cognitoSecretBackend, error) {
	b := cognitoSecretBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(cognitoHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathsRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathAccessToken(&b),
			},
		),
		BackendType: logical.TypeLogical,
	}

	b.getClient = newClient

	return &b, nil
}

// reset clears the backend's cached client
// This is used when the configuration changes and a new client should be
// created with the updated settings.
func (b *cognitoSecretBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	//b.settings = nil
	//b.client = nil
}

func (b *cognitoSecretBackend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *cognitoSecretBackend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession())

	// Create service client value configured for credentials
	// from assumed role.
	cognitoClient := cognitoidentityprovider.New(sess, &aws.Config{Region: aws.String("eu-west-1")})

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("Could not generate UUID: {{err}}", err)
	}

	emailID := "vault" + keyID[5:] + "@wealthwizards.io"

	userPoolID := "eu-west-1_hlXkPbbOY"

	password := "pa$$word90123"

	newUserData := &cognitoidentityprovider.AdminCreateUserInput{
		MessageAction:     aws.String("SUPPRESS"),
		TemporaryPassword: aws.String(password),
		UserAttributes: []*cognitoidentityprovider.AttributeType{
			{
				Name:  aws.String("email"),
				Value: aws.String(emailID),
			},
			{
				Name:  aws.String("email_verified"),
				Value: aws.String("true"),
			},
		},
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(emailID),
	}

	_, err = cognitoClient.AdminCreateUser(newUserData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not create user: {{err}}", err)
	}

	addUserToGroupData := &cognitoidentityprovider.AdminAddUserToGroupInput{
		GroupName:  aws.String("adviser"),
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(emailID),
	}
	_, err = cognitoClient.AdminAddUserToGroup(addUserToGroupData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not add user to group: {{err}}", err)
	}

	adminInitiateAuthData := &cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow: aws.String("ADMIN_NO_SRP_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(emailID),
			"PASSWORD": aws.String(password),
		},
		ClientId:   aws.String("726mt5k78c6hmn0611t2orljle"),
		UserPoolId: aws.String(userPoolID),
	}
	sessionResponse, err := cognitoClient.AdminInitiateAuth(adminInitiateAuthData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not init auth: {{err}}", err)
	}

	adminRespondToAuthChallengeData := &cognitoidentityprovider.AdminRespondToAuthChallengeInput{
		ChallengeName: aws.String("NEW_PASSWORD_REQUIRED"),
		ChallengeResponses: map[string]*string{
			"USERNAME":     aws.String(emailID),
			"NEW_PASSWORD": aws.String(password),
		},
		ClientId:   aws.String("726mt5k78c6hmn0611t2orljle"),
		Session:    aws.String(*sessionResponse.Session),
		UserPoolId: aws.String(userPoolID),
	}
	//authenticationResult
	_, err = cognitoClient.AdminRespondToAuthChallenge(adminRespondToAuthChallengeData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not respond to auth challenge: {{err}}", err)
	}

	rawData := map[string]interface{}{
		"username": emailID,
		"password": password,
		//			"authenticationResult": authenticationResult,
	}

	resp := &logical.Response{
		Data: rawData,
	}
	return resp, nil

}

const cognitoHelp = `
The Cognito backend is a secrets backend for AWS Cognito.
`
