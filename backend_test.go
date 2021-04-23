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

func (c *mockClient) getAccessToken(cognitoPoolUrl, appClientSecret string) (map[string]interface{}, error) {

	rawData := map[string]interface{}{
		"access_token": "eyJraWQiOiIwa2t0UU04ZjhYTXB2R21zUCtIRUljdWhWdWhJVFZpbjUrWjY3RllSK013PSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIxcmxxNjlxZW4zaTZlOW5kNGZnazE1cnJ1ciIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYWR2aXNlci1odWJcL3JlYWRXcml0ZUFjY2VzcyIsImF1dGhfdGltZSI6MTYxOTE3MzU4NSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTFfaGxYa1BiYk9ZIiwiZXhwIjoxNjE5MTc3MTg1LCJpYXQiOjE2MTkxNzM1ODUsInZlcnNpb24iOjIsImp0aSI6ImY0NTU3NTQzLWFhMzAtNDM0ZS05MTgyLTlhOWRmYzJiYjFiZiIsImNsaWVudF9pZCI6IjFybHE2OXFlbjNpNmU5bmQ0ZmdrMTVycnVyIn0.STennOu_6nR9UlNFCnfAEkeRSUai-x_Tv8Z_PrWNp3OlFIrAwCAoknQ0_xl0inZm6GBX3796W3KmkVtT94qTqvGY_9xY3JMaj8Ce9IzL_ek3xtgRa0banibNu7HwCELcIKr3_AO5CrXWfxTo6DaHbYA3RIXSZfaMjb_WJJAdMOOmUfAEK5WALbMUT-UC57KERGzvHcryjbu5r1H9UPaSVn-vKw02wLlnbpfMSCy0EqmXHy1mw7mlxM4vsHt50i9Cc664egHRlsgV-Pn_N-x5eCjFV6Cxwit78TBqRMypFd3TkXbErOdZWpXbMvVjQ0geh7ayBnMVSXxA6q6W3m2hvQ",
		"expires_in":   3600,
		"token_type":   "Bearer",
	}

	return rawData, nil
}

func newMockClient() *mockClient {
	return &mockClient{}
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

	mockClient := newMockClient()
	b.getClient = func() (client, error) {
		return mockClient, nil
	}

	if initConfig {
		cfg := map[string]interface{}{
			"cognito_pool_url":  "testCognitoPoolUrl",
			"app_client_secret": "testAppClientSecret",
		}

		testConfigCreate(t, b, config.StorageView, cfg)
	}

	return b, config.StorageView
}
