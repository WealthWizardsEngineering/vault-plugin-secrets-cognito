package cognito

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) {
	t.Helper()
	testConfigCreateUpdate(t, b, logical.CreateOperation, s, d)
}

func testConfigCreateUpdate(t *testing.T, b logical.Backend, op logical.Operation, s logical.Storage, d map[string]interface{}) {
	t.Helper()

	// save and restore the client since the config change will clear it
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      "config",
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
