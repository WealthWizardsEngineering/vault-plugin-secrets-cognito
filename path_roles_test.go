package cognito

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/logical"
	"sort"
	"testing"
)

func TestRoleCreate(t *testing.T) {
	b, s := getTestBackend(t, true)

	t.Run("Access Token role", func(t *testing.T) {
		accessTokenRole1 := map[string]interface{}{
			"credential_type":   "access_token",
			"cognito_pool_url":  "aa",
			"app_client_secret": "aaa",
		}

		accessTokenRole2 := map[string]interface{}{
			"credential_type":   "access_token",
			"cognito_pool_url":  "bb",
			"app_client_secret": "bbb",
		}

		// Verify basic updates of the name role
		name := generateUUID()
		testRoleCreate(t, b, s, name, accessTokenRole1)

		resp, err := testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, accessTokenRole1, resp.Data)

		testRoleCreate(t, b, s, name, accessTokenRole2)

		resp, err = testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, accessTokenRole2, resp.Data)
	})
	t.Run("User role", func(t *testing.T) {
		userRole1 := map[string]interface{}{
			"credential_type":    "user",
			"region":             "aa",
			"client_id":          "aaa",
			"user_pool_id":       "aaaa",
			"group":              "aaaaa",
			"dummy_email_domain": "aaaaaa",
		}

		userRole2 := map[string]interface{}{
			"credential_type":    "user",
			"region":             "bb",
			"client_id":          "bbb",
			"user_pool_id":       "bbbb",
			"group":              "bbbbb",
			"dummy_email_domain": "bbbbbb",
		}

		// Verify basic updates of the name role
		name := generateUUID()
		testRoleCreate(t, b, s, name, userRole1)

		resp, err := testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, userRole1, resp.Data)

		testRoleCreate(t, b, s, name, userRole2)

		resp, err = testRoleRead(t, b, s, name)
		assertErrorIsNil(t, err)

		equal(t, userRole2, resp.Data)
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
		"cognito_pool_url": "aa",
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
		"cognito_pool_url": "aa",
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
