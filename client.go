package cognito

import (
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"io/ioutil"
	"net/http"
)

type client interface {
	getAccessToken(cognitoPoolUrl string, appClientSecret string) (map[string]interface{}, error)
}

type clientImpl struct {
}

func newClient() (client, error) {
	p := &clientImpl{}

	return p, nil
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
