package cognito

import (
	"context"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

type mockClient struct {
}

func (c *mockClient) deleteUser(region string, userPoolId string, username string) error {
	return nil
}

func (c *mockClient) getClientCredentialsGrant(cognitoPoolDomain, appClientId, appClientSecret string) (map[string]interface{}, error) {

	rawData := map[string]interface{}{
		"access_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"expires_in":   3600,
		"token_type":   "Bearer",
	}

	return rawData, nil
}

func (c *mockClient) getNewUser(region string, appClientId string, userPoolId string, group string, dummyEmailDomain string) (map[string]interface{}, error) {

	rawData := map[string]interface{}{
		"username": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"password": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	}

	return rawData, nil
}

func getTestBackend(t *testing.T, initConfig bool) (*cognitoSecretBackend, logical.Storage) {
	b, _ := newBackend()

	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	if initConfig {
		cfg := map[string]interface{}{
			"cognito_pool_domain": "testCognitoPoolDomain",
			"app_client_id":       "testAppClientId",
			"app_client_secret":   "testAppClientSecret",
		}

		testConfigCreate(t, b, config.StorageView, cfg)
	}

	b.client, _ = getMockClient()

	return b, config.StorageView
}
func getMockClient() (client, error) {

	c := &mockClient{}

	return c, nil
}
