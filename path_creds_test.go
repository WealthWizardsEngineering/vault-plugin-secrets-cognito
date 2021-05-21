package cognito

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
	"time"
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

	// verify role TTLs are reflected in secret
	t.Run("TTLs", func(t *testing.T) {
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

		equal(t, 0*time.Second, resp.Secret.TTL)
		equal(t, 0*time.Second, resp.Secret.MaxTTL)

		roleUpdate := map[string]interface{}{
			"ttl":     20,
			"max_ttl": 30,
		}
		testRoleCreate(t, b, s, name, roleUpdate)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "creds/" + name,
			Storage:   s,
		})

		assertErrorIsNil(t, err)

		equal(t, 20*time.Second, resp.Secret.TTL)
		equal(t, 30*time.Second, resp.Secret.MaxTTL)
	})
}
