package cognito

import (
	b64 "encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"
)

type client interface {
	deleteUser(region string, userPoolId string, username string) error
	getClientCredentialsGrant(cognitoPoolDomain string, appClientId string, appClientSecret string) (map[string]interface{}, error)
	getNewUser(region string, appClientId string, userPoolId string, group string, dummyEmailDomain string) (map[string]interface{}, error)
}

type clientImpl struct {
	AwsAccessKeyId     string
	AwsSecretAccessKey string
	AwsSessionToken    string
}

func (c *clientImpl) deleteUser(region string, userPoolId string, username string) error {
	config := aws.NewConfig()

	if c.AwsAccessKeyId != "" {
		creds := credentials.NewStaticCredentials(c.AwsAccessKeyId, c.AwsSecretAccessKey, c.AwsSessionToken)
		config = config.WithCredentials(creds)
	}
	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession(config))

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

func (c *clientImpl) getClientCredentialsGrant(cognitoPoolDomain string, appClientId string, appClientSecret string) (map[string]interface{}, error) {

	var rawData map[string]interface{}

	encodedAppClientSecret := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", appClientId, appClientSecret)))

	myClient := &http.Client{}
	postReq, _ := http.NewRequest("POST", fmt.Sprintf("https://%s/oauth2/token?grant_type=client_credentials&client_id=%s", cognitoPoolDomain, appClientId), nil)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedAppClientSecret))
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

func (c *clientImpl) getNewUser(region string, appClientId string, userPoolId string, group string, dummyEmailDomain string) (map[string]interface{}, error) {

	config := aws.NewConfig()

	if c.AwsAccessKeyId != "" {
		creds := credentials.NewStaticCredentials(c.AwsAccessKeyId, c.AwsSecretAccessKey, c.AwsSessionToken)
		config = config.WithCredentials(creds)
	}
	// Initial credentials loaded from SDK's default credential chain. Such as
	// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
	// Role. These credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession(config))

	// Create service client value configured for credentials
	// from assumed role.
	cognitoClient := cognitoidentityprovider.New(sess, &aws.Config{Region: aws.String(region)})

	keyID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, errwrap.Wrapf("Could not generate UUID: {{err}}", err)
	}

	emailID := "vault" + keyID[5:] + "@" + dummyEmailDomain
	password := generatePassword()

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
		ClientId:   aws.String(appClientId),
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
		ClientId:   aws.String(appClientId),
		Session:    aws.String(*sessionResponse.Session),
		UserPoolId: aws.String(userPoolId),
	}

	authenticationResult, err := cognitoClient.AdminRespondToAuthChallenge(adminRespondToAuthChallengeData)
	if err != nil {
		return nil, errwrap.Wrapf("Could not respond to auth challenge: {{err}}", err)
	}

	rawData := map[string]interface{}{
		"username":      emailID,
		"password":      password,
		"access_token":  aws.String(*authenticationResult.AuthenticationResult.AccessToken),
		"expires_in":    aws.Int64(*authenticationResult.AuthenticationResult.ExpiresIn),
		"id_token":      aws.String(*authenticationResult.AuthenticationResult.IdToken),
		"refresh_token": aws.String(*authenticationResult.AuthenticationResult.RefreshToken),
		"token_type":    aws.String(*authenticationResult.AuthenticationResult.TokenType),
	}

	return rawData, nil
}

func generatePassword() string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	specials := "~=+%^*/()[]{}/!@#$?|"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	length := 32
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	str := string(buf) // E.g. "3i[g0|)z"
	return str
}
