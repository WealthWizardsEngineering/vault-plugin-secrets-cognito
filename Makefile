GOARCH = amd64
TEST?=$$(go list ./... | grep -v /vendor/)

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/vault-plugin-secrets-cognito-${OS}-${GOARCH} cmd/vault-plugin-secrets-cognito/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable -path=cognito vault-plugin-secrets-cognito-${OS}-${GOARCH}

clean:
	rm -f ./vault/plugins/vault-plugin-secrets-cognito-${OS}-${GOARCH}

fmt:
	go fmt $$(go list ./...)

# test runs all tests
test: generate
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package"; \
		exit 1; \
	fi
	VAULT_ACC=1 go test $(TEST) -v $(TESTARGS) -timeout 45m

generate:
	go generate $(go list ./... | grep -v /vendor/)

.PHONY: build clean fmt start enable test generate
