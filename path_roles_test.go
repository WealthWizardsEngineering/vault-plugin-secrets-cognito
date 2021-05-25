package cognito

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"sort"
	"testing"
	"time"
)

func TestRoleCreate(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("Client credentials grant role", func(t *testing.T) {
		clientCredentialGrantRole1 := map[string]interface{}{
			"credential_type":     "client_credentials_grant",
			"cognito_pool_domain": "aa",
			"app_client_secret":   "aaa",
		}

		clientCredentialGrantRole2 := map[string]interface{}{
			"credential_type":     "client_credentials_grant",
			"cognito_pool_domain": "bb",
			"app_client_secret":   "bbb",
		}

		// Verify basic updates of the name role
		name := generateUUID()
		testRoleCreate(t, b, s, name, clientCredentialGrantRole1)

		resp, err := testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, clientCredentialGrantRole1, resp.Data)

		testRoleCreate(t, b, s, name, clientCredentialGrantRole2)

		resp, err = testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, clientCredentialGrantRole2, resp.Data)
	})
	t.Run("User role", func(t *testing.T) {
		userRole1 := map[string]interface{}{
			"credential_type":    "user",
			"region":             "aa",
			"app_client_id":      "aaa",
			"user_pool_id":       "aaaa",
			"group":              "aaaaa",
			"dummy_email_domain": "aaaaaa",
			"ttl":                int64(0),
			"max_ttl":            int64(0),
		}

		userRole2 := map[string]interface{}{
			"credential_type":    "user",
			"region":             "bb",
			"app_client_id":      "bbb",
			"user_pool_id":       "bbbb",
			"group":              "bbbbb",
			"dummy_email_domain": "bbbbbb",
			"ttl":                int64(300),
			"max_ttl":            int64(3000),
		}

		// Verify basic updates of the name role
		name := generateUUID()
		testRoleCreate(t, b, s, name, userRole1)

		resp, err := testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		convertRespTypes(resp.Data)
		equal(t, userRole1, resp.Data)

		testRoleCreate(t, b, s, name, userRole2)

		resp, err = testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		convertRespTypes(resp.Data)
		equal(t, userRole2, resp.Data)
	})
	t.Run("User Optional role TTLs", func(t *testing.T) {
		testRole := map[string]interface{}{
			"credential_type":    "user",
			"region":             "cc",
			"app_client_id":      "ccc",
			"user_pool_id":       "cccc",
			"group":              "ccccc",
			"dummy_email_domain": "cccccc",
		}

		// Verify that ttl and max_ttl are 0 if not provided
		name := generateUUID()
		testRoleCreate(t, b, s, name, testRole)

		testRole["ttl"] = int64(0)
		testRole["max_ttl"] = int64(0)

		resp, err := testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		convertRespTypes(resp.Data)
		equal(t, testRole, resp.Data)
	})

	t.Run("User Role TTL Checks", func(t *testing.T) {
		b, s := getTestBackend(t, true)

		const skip = -999
		tests := []struct {
			ttl      int64
			maxTTL   int64
			expError bool
		}{
			{5, 10, false},
			{5, skip, false},
			{skip, 10, false},
			{100, 100, false},
			{101, 100, true},
			{101, 0, false},
		}

		for i, test := range tests {
			role := map[string]interface{}{
				"credential_type":    "user",
				"region":             "cc",
				"app_client_id":      "ccc",
				"user_pool_id":       "cccc",
				"group":              "ccccc",
				"dummy_email_domain": "cccccc",
			}

			if test.ttl != skip {
				role["ttl"] = test.ttl
			}
			if test.maxTTL != skip {
				role["max_ttl"] = test.maxTTL
			}
			name := generateUUID()
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "roles/" + name,
				Data:      role,
				Storage:   s,
			})
			assertErrorIsNil(t, err)

			if resp.IsError() != test.expError {
				t.Fatalf("\ncase %d\nexp error: %t\ngot: %v", i, test.expError, err)
			}
		}
	})
}

func TestRoleList(t *testing.T) {
	b, s := getTestBackend(t, true)

	// Verify empty list
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("expected nil error, actual:%#v", err.Error())
	}

	if resp.Data["keys"] != nil {
		t.Fatalf("expected nil, actual: %#v", resp.Data["keys"])
	}

	// Add some roles and verify the resulting list
	role := map[string]interface{}{
		"cognito_pool_domain": "aa",
	}
	testRoleCreate(t, b, s, "r1", role)
	testRoleCreate(t, b, s, "r2", role)
	testRoleCreate(t, b, s, "r3", role)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	assertErrorIsNil(t, err)

	exp := []string{"r1", "r2", "r3"}
	sort.Strings(resp.Data["keys"].([]string))
	equal(t, exp, resp.Data["keys"])

	// Delete a role and verify list is updated
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/r2",
		Storage:   s,
	})
	assertErrorIsNil(t, err)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
	assertErrorIsNil(t, err)

	exp = []string{"r1", "r3"}
	sort.Strings(resp.Data["keys"].([]string))
	equal(t, exp, resp.Data["keys"])
}

func TestRoleDelete(t *testing.T) {
	b, s := getTestBackend(t, true)
	name := "test_role"
	nameAlt := "test_role_alt"

	role := map[string]interface{}{
		"cognito_pool_domain": "aa",
	}

	// Create two roles and verify they're present
	testRoleCreate(t, b, s, name, role)
	testRoleCreate(t, b, s, nameAlt, role)

	// Delete one role and verify it is gone, and the other remains
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Storage:   s,
	})
	assertErrorIsNil(t, err)

	resp, err = testRoleRead(t, b, s, name)
	if resp != nil || err != nil {
		t.Fatalf("expected nil response and error, actual:%#v and %#v", resp, err.Error())
	}

	resp, err = testRoleRead(t, b, s, nameAlt)
	assertErrorIsNil(t, err)
	if resp == nil {
		t.Fatalf("expected non-nil response, actual:%#v", resp)
	}

	// Verify that delete against a missing role is a succesful no-op
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/not_a_role",
		Storage:   s,
	})
	if resp != nil || err != nil {
		t.Fatalf("expected nil response and error, actual:%#v and %#v", resp, err)
	}
}

// Utility function to create a role and fail on errors
func testRoleCreate(t *testing.T, b *cognitoSecretBackend, s logical.Storage, name string, d map[string]interface{}) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
}

// Utility function to read a role and return any errors
func testRoleRead(t *testing.T, b *cognitoSecretBackend, s logical.Storage, name string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("roles/%s", name),
		Storage:   s,
	})
}

// Utility function to convert response types back to the format that is used as
// input in order to streamline the comparison steps.
func convertRespTypes(data map[string]interface{}) {
	data["ttl"] = int64(data["ttl"].(time.Duration))
	data["max_ttl"] = int64(data["max_ttl"].(time.Duration))
}
