package cognito

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type cognitoSecretBackend struct {
	*framework.Backend

	client client
	lock   sync.RWMutex
}

var _ logical.Factory = Factory

// Factory configures and returns Cognito backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*cognitoSecretBackend, error) {
	b := cognitoSecretBackend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(cognitoHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			pathsRole(&b),
			[]*framework.Path{
				pathConfig(&b),
				pathCreds(&b),
			},
		),
		Secrets: []*framework.Secret{
			secretUser(&b),
		},
		BackendType: logical.TypeLogical,
	}

	return &b, nil
}

func (b *cognitoSecretBackend) getClient() (client, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	if b.client != nil {
		return b.client, nil
	}

	c := &clientImpl{}

	b.client = c

	return c, nil
}

// reset clears the backend's cached client
// This is used when the configuration changes and a new client should be
// created with the updated settings.
func (b *cognitoSecretBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = nil
}

func (b *cognitoSecretBackend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

const cognitoHelp = `
The Cognito backend is a secrets backend for AWS Cognito.
`
