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
	//"https://turo-blue-rpp.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=client_credentials&client_id=1rlq69qen3i6e9nd4fgk15rrur", nil)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Authorization", appClientSecret)
	//	"Basic MXJscTY5cWVuM2k2ZTluZDRmZ2sxNXJydXI6bTZnZWoxNDJpNDl1OW85N3NnbXFsaG1nMDI0MzFuaWZucnJydmQyMmFpNWJwMzB2MnNx")
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
