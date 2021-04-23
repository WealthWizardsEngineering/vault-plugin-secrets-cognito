# Vault Cognito Secrets Plugin

Vault Cognito is a secrets engine plugin for [AWS Cognito](https://aws.amazon.com/cognito/).

## Usage

All commands can be run using the provided [Makefile](./Makefile). However, it may be instructive to look at the commands to gain a greater understanding of how Vault registers plugins. Using the Makefile will result in running the Vault server in `dev` mode. Do not run Vault in `dev` mode in production. The `dev` server allows you to configure the plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin binaries must be manually registered.

This will build the plugin binary and start the Vault dev server:

```
# Build Cognito plugin and start Vault dev server with plugin automatically registered
$ make
```

Now open a new terminal window and run the following commands:

```
# Open a new terminal window and export Vault dev server http address
$ export VAULT_ADDR='http://127.0.0.1:8200'

# Enable the Cognito plugin
$ make enable
```

Configure a role:
```
%vault write cognito/roles/my-cognito-pool app_client_secret="Basic AAAAAAA" cognito_pool_url="https://my-user-pool.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=client_credentials&client_id=111111111"
```

And get a token from it:
```
% vault read cognito/creds/my-cognito-pool
Key             Value
---             -----
access_token    ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
expires_in      3600
token_type      Bearer
```
