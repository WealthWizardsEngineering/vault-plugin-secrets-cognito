package cognito

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func TestSPRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	// verify basic cred issuance
	t.Run("Basic Role", func(t *testing.T) {
		name := generateUUID()
		testRole := map[string]interface{}{
			"cognito_pool_url":  "my url",
			"app_client_secret": "my secret",
		}
		testRoleCreate(t, b, s, name, testRole)

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		if resp.IsError() {
			t.Fatalf("expected no response error, actual:%#v", resp.Error())
		}

		assertKeyExists(t, resp.Data, "access_token")
	})
}
