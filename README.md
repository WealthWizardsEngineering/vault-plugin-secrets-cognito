# Vault Cognito Secrets Plugin

The Vault Cognito secrets engine allows you to request credentials from [AWS Cognito](https://aws.amazon.com/cognito/).

AWS cognito is used as an authentication engine based around JSON Web Tokens (JWT).

# Motivation

At Wealth Wizards we have adopted Cognito for our application authentication and have been moving towards JWT
everywhere. Which allows us to authenticate and authorised both human users and automation users based on their JWT
tokens issued from Cognito.

As our user groups/permissions have evolved we have the challenge to test multiple different types of users, previously
we have had statically created users in our test Cognito user pools and shared the credentials in the Vault K/V secrets
backend. These static/stored credentials become well known and prevent us seeing who is using them and stops us from
revoking access from individuals. Introducing this secrets backend allows our tests to request the access that they need
when they need it, with the credentials revoked once the tests have finished.

We also have automated processes that need access for a short period of times to production systems, rather than
introduce static credentials or alternative authentication mechanisms, we can use Vault to issue JWT tokens for these
processes.

# About Cognito

AWS Cognito provides JWT based authentication and authorisation and can authenticate users from an internal user
database as well as third parties, e.g. via SAML. Cognito can be used in stand along services, but is easily integrated
with many AWS serverless components, e.g. API gateway, AppSync.

For more information about Cognito read: [What Is Amazon Cognito?](https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html).

A Cognito User Pool is a user directory in Amazon Cognito and provides sign in services which authenticates users and
allows them to get tokens for authorisation, see [Using Tokens with User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html)
for more details.

In order to interact with Cognito, an App Client is required. This is an entity within a user pool that has permission t
call unauthenticated API operations, e.g. sign in. To call these API operations you need an app client id and optionally
a client secret.

As well as providing tokens for a user, an app client can be used to perform machine to machine
authentication, refered to as [client credential grant](https://aws.amazon.com/blogs/mobile/understanding-amazon-cognito-user-pool-oauth-2-0-grants/).
A good explanation of Cognito and setting this up is given in this article: [Server to Server Auth with Amazon Cognito
](https://lobster1234.github.io/2018/05/31/server-to-server-auth-with-amazon-cognito/).

# Installation

To begin plugin installation, either download a release or build from source for your chosen OS and architecture.

## From release

Always download the latest stable release from the releases section.

## From source

Build for your target OS, the plugin binary will be available in `vault/plugins`.

### Build for current architecture

```
make build
```

### Build for Linux/AMD64.

```
OS=linux make build
```

### Build for Mac/AMD64.

```
OS=darwin make build
```

## Vault setup

1. Move the desired plugin binary into your Vault's configured `plugin_directory`.

```
mv vault-plugin-secrets-cognito-<os>-<arch> <plugin_directory>/cognito
```

2. If you downloaded it from releases then you may need to change the permissions
   
```
chmod u+x cognito 
```

3. Enable the secrets backend

```
vault secrets enable -path=cognito cognito
```

# Usage

## Configuration

There are two types of roles that can be configured and is determined by the `credential_type` value in the configured
role:

1. `access_token` - This uses an app client secret to generates an JWT access token that can be used as a bearer access
   token
2. `user` - This creates a user in configured the user pool and returns the username, password and JWT tokens

To create a role:

```
vault write cognito/roles/my-cognito-role credential_type=<access_token/user> ...
```

The other parameters are defined below for each type.

### Access token / client credential grant role

Create a role that determines how to get an access token:

```
vault write cognito/roles/my-cognito-access-token credential_type=access_token app_client_secret="Basic AAAAAAA" cognito_pool_url="https://my-user-pool.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=client_credentials&client_id=111111111"
```

Where
* credential_type: `access_token`
* app_client_secret: The secret created in your [cognito pool app client](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html)
* cognito_pool_url: The [token URL endpoint](https://docs.amazonaws.cn/en_us/cognito/latest/developerguide/token-endpoint.html)
  for the user pool e.g. https://turo-blue-rpp.auth.eu-west-1.amazoncognito.com/oauth2/token?grant_type=client_credentials&client_id=123456789

### User role

The user role creates a user in the configured Cognito User pool, Vault must have permissions to run the Admin API
commands. The user is created, and the forced change password is worked through in order to produce a user that is ready
to be used with your application.

Create a role that determines how to get a user and associated tokens:

```
$ vault write cognito/roles/my-congito-user credential_type=user region=eu-west-1 client_id=abcdefghijeck user_pool_id=eu-west-1_abcdefg group=mycognitogroup dummy_email_domain=example.com
```

Where
* credential_type: `user`
* region: The AWS region that your cognito pool exists, e.g. us-east-1
* client_id: The app client id
* user_pool_id: The cognito pool id, e.g. eu-west-1_abcdefg
* group: The Cognito user group to assign this user to
* dummy_email_domain: The user will be created using an email address, set the domain to use, it does not need to be a
  real domain as emails are not sent.
* ttl: The default time to live for this user, before is revoked

Note that the TTL is how long the user exists, the tokens returned will have their own TTLs based on the app client
configuration and may be valid for longer than the user. However, the refresh token will be rejected once the user has
been revoked.

#### AWS configuration

Vault requires permissions to manage users in your Cognito User Pool, in order to add.

Example IAM policy: 

```
some policy

```

## Usage

### Access token / client credential grant role

```
vault read cognito/creds/my-cognito-access-token
Key             Value
---             -----
access_token    ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
expires_in      3600
token_type      Bearer
```

Note that the expiration (`expires_in`) is determined by the app client configuration and cannot be renewed either via
Vault or cognito as there is no accompanying refresh token. However, it's trivial to retrieve a new one if required.

You can then use the token for Bearer authentication as part of a http requests by setting the `Authorization`
header.

`curl --location --request GET 'https://my-api.example.com' --header 'Authorization: ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'`

### User role

```
vault read cognito/creds/my-cognito-user
Key                Value
---                -----
lease_id           cognito/creds/my-cognito-user/abcdefg
lease_duration     300s
lease_renewable    true
access_token       aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expires_in         3600
id_token           iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
password           pppppppppppppppppppppppppppppp
refresh_token      rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr
token_type         Bearer
username           vaultc21-0074-0574-988c-bd3ae161ea5d@example.com
```

Note that the expiration (`expires_in`) is determined by the app client configuration. However, the refresh token can be
used to get new access/id tokens from Cognito as long as the user hasn't been revoked by Vault.

# Contributing

## Running locally

All commands can be run using the provided [Makefile](./Makefile). However, it may be instructive to look at the
commands to gain a greater understanding of how Vault registers plugins. Using the Makefile will result in running the
Vault server in `dev` mode. Do not run Vault in `dev` mode in production. The `dev` server allows you to configure the
plugin directory as a flag, and automatically registers plugin binaries in that directory. In production, plugin
binaries must be manually registered.

This will build the plugin binary and start the Vault dev server:

```
make
```

Now open a new terminal window and run the following commands:

```
export VAULT_ADDR='http://127.0.0.1:8200'

make enable
```

## Tests

Run the tests:

```
$ make test
```

## CircleCI

CircleCI builds and tests thie project. Aretfacts are created on each build and made available.

## Releasing

Artefacts from CircleCI can be uploaded to GitHub as releases to this repository.
