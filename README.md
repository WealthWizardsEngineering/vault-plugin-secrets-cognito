# Vault Cognito Secrets Plugin

Vault Cognito is a secrets engine plugin for [AWS Cognito](https://aws.amazon.com/cognito/).

## Usage

All commands can be run using the provided [Makefile](./Makefile). However, it may be instructive to look at the commands to gain a greater understanding of how Vault registers plugins. Using the Makefile will result in running the Vault server in `dev` mode. Do not run Vault in `dev` mode in production. The `dev` server allows you to configure the plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin binaries must be manually registered.

This will build the plugin binary and start the Vault dev server:

```
$ make
```

Now open a new terminal window and run the following commands:

```
$ export VAULT_ADDR='http://127.0.0.1:8200'

$ make enable
```

### Configure a access token role

```
$ vault write cognito/roles/my-cognito-pool app_client_secret="Basic AAAAAAA" cognito_pool_url="https://my-user-pool.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=client_credentials&client_id=111111111"
```

Where
* credential_type: either `access_token` or `user`
* app_client_secret
* cognito_pool_url

And get a token from it:
```
$ vault read cognito/creds/my-cognito-access-token
Key             Value
---             -----
access_token    ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
expires_in      3600
token_type      Bearer
```

### Configure a user role

```
$ vault write cognito/roles/my-congito-user credential_type=user region=eu-west-1 client_id=abcdefghijeck user_pool_id=eu-west-1_abcdefg group=mycognitogroup dummy_email_domain=example.com
```

And get a token from it: 

```
$ vault read cognito/creds/turo-green-rpp-user 
Key         Value
---         -----
password    somepassword
username    vaulta87-7e13-8620-0e3e-3c704f8d8b8f@example.com
```
## Tests

Run the tests:

```
$ make test
```
