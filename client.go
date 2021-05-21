package cognito

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"io/ioutil"
	"net/http"
)

type client interface {
	deleteUser(region string, userPoolId string, username string) error
	getAccessToken(cognitoPoolUrl string, appClientSecret string) (map[string]interface{}, error)
	getNewUser(region string, clientId string, userPoolId string, group string, dummyEmailDomain string) (map[string]interface{}, error)
}

type clientImpl struct {
}

func newClient() (client, error) {
	p := &clientImpl{}

	return p, nil
}

func (c *clientImpl) deleteUser(region string, userPoolId string, username string) error {
	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession())

	// Create service client value configured for credentials
	// from assumed role.
	cognitoClient := cognitoidentityprovider.New(sess, &aws.Config{Region: aws.String(region)})
	deleteUserData := &cognitoidentityprovider.AdminDeleteUserInput{
		UserPoolId: aws.String(userPoolId),
		Username:   aws.String(username),
	}

	_, err := cognitoClient.AdminDeleteUser(deleteUserData)
	return err
}

// Get an access token
func (c *clientImpl) getAccessToken(cognitoPoolUrl string, appClientSecret string) (map[string]interface{}, error) {

	var rawData map[string]interface{}

	myClient := &http.Client{}
	postReq, _ := http.NewRequest("POST", cognitoPoolUrl, nil)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Authorization", appClientSecret)
	postResp, err := myClient.Do(postReq)

	fetchedData, _ := ioutil.ReadAll(postResp.Body)

	if err != nil {
		return nil, errwrap.Wrapf("Token request failed: {{err}}", err)
	}

	if fetchedData == nil {
		return nil, fmt.Errorf("Token was empty")
	}

	if err := jsonutil.DecodeJSON(fetchedData, &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	return rawData, nil
}

func (c *clientImpl) getNewUser(region string, clientId string, userPoolId string, group string, dummyEmailDomain string) (map[string]interface{}, error) {

	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession())

	// Create service client value configured for credentials
	// from assumed role.
	cognitoClient := cognitoidentityprovider.New(sess, &aws.Config{Region: aws.String(region)})

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("Could not generate UUID: {{err}}", err)
	}

	emailID := "vault" + keyID[5:] + "@" + dummyEmailDomain
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
		UserPoolId: aws.String(userPoolId),
		Username:   aws.String(emailID),
	}

	_, err = cognitoClient.AdminCreateUser(newUserData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not create user: {{err}}", err)
	}

	addUserToGroupData := &cognitoidentityprovider.AdminAddUserToGroupInput{
		GroupName:  aws.String(group),
		UserPoolId: aws.String(userPoolId),
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
		ClientId:   aws.String(clientId),
		UserPoolId: aws.String(userPoolId),
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
		ClientId:   aws.String(clientId),
		Session:    aws.String(*sessionResponse.Session),
		UserPoolId: aws.String(userPoolId),
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

	return rawData, nil

}
