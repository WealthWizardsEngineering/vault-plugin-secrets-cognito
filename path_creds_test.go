package cognito

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func TestAccessTokenRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("Access Token Role", func(t *testing.T) {
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

		exp := map[string]interface{}{
			"access_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		equal(t, exp, resp.Data)
	})
}

func TestUserRead(t *testing.T) {
	b, s := getTestBackend(t, true)

	// verify basic cred issuance
	t.Run("User Role", func(t *testing.T) {
		name := generateUUID()
		testRole := map[string]interface{}{
			"credential_type": "user",
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

		exp := map[string]interface{}{
			"username": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"password": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		}
		equal(t, exp, resp.Data)
	})
}
