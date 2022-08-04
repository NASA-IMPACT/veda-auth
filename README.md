# VEDA Auth System

This codebase represents the Cognito-based authentication system used for the VEDA project.

Note: This is for setting up the user pools and managing applications, it is _not_ for managing users. Managing users should be instead done via AWS

## Running the client

First you need to setup the client with the settings for the Cognito user pool of interest.

```bash
cp env.example .env
```

Assuming you already have a username and password associated with the Cognito user pool of interest, you can run the client to generate tokens and AWS credentials:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/tmp-creds-example.py
```

## Expanding

The codebase intends to be expandable to meet VEDA's needs as the project grows. Currently, the stack exposes two methods to facilitate customization.

### `stack.add_programmatic_client(client_identifier)`

### `stack.add_service_client(client_identifier)`

Add a service that will be authenticating with the VEDA system. This utilizes the [`client_credentials` flow](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/), meaning that the credentials represent a _service_ rather than any particular _user_:

> the client credentials grant is typically intended to provide credentials to an application in order to authorize machine-to-machine requests. Note that, to use the client credentials grant, the corresponding user pool app client must have an associated app client secret. ([source](https://aws.amazon.com/blogs/mobile/understanding-amazon-cognito-user-pool-oauth-2-0-grants/))

Calling `.add_service_client()` with a unique identifier will create a [user pool app client](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html?icmpid=docs_cognito_console_help_panel) to represent this service. Credentials for the generated app client will be stored in an AWS SecretsManager Secret with an ID following the format of `{veda_auth_stack_name}/{service_identifier}`. These credentials can be retrieved by the related service and used to request an access token to be used to access any API that requires a valid auth token.

A demonstration of how these credentials can be retrieve and used to generate a JWT for a service, see `scripts/get-service-token.py`
