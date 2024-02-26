# VEDA Auth System

This codebase represents the Cognito-based authentication system used for the VEDA project.

Note: This is for setting up the user pools and managing applications, it is _not_ for managing users. Managing users should be instead done via AWS

## Running the example client

The example client requires the following configuration to be available via environment variables or in a `.env` file:

- `IDENTITY_POOL_ID`, the ID of the Cognito identity pool, e.g. `us-west-2:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- `USER_POOL_ID`, the ID of Cognito user pool, e.g. `us-west-2_XXXXXXXXX`
- `CLIENT_ID`, the ID of the Cognito client, e.g. `XXXxxxxxxxxxxxxxxxxxxxXXXX`

Assuming you already have a username and password associated with the Cognito user pool of interest, you can run the client to generate tokens and AWS credentials:

```bash
python3 -m pip install -r requirements.txt
python3 scripts/tmp-creds-example.py
```

## Expanding

The codebase intends to be expandable to meet VEDA's needs as the project grows. Currently, the stack exposes two methods to facilitate customization.

### Adding a Resource Server

A resource server is a service that is to be protected by auth.

### `stack.add_programmatic_client(client_identifier)`

### `stack.add_service_client(client_identifier)`

Add a service that will be authenticating with the VEDA system. This utilizes the [`client_credentials` flow](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/), meaning that the credentials represent a _service_ rather than any particular _user_:

> the client credentials grant is typically intended to provide credentials to an application in order to authorize machine-to-machine requests. Note that, to use the client credentials grant, the corresponding user pool app client must have an associated app client secret. ([source](https://aws.amazon.com/blogs/mobile/understanding-amazon-cognito-user-pool-oauth-2-0-grants/))

Calling `.add_service_client()` with a unique identifier will create a [user pool app client](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html?icmpid=docs_cognito_console_help_panel) to represent this service. Credentials for the generated app client will be stored in an AWS SecretsManager Secret with an ID following the format of `{veda_auth_stack_name}/{service_identifier}`. These credentials can be retrieved by the related service and used to request an access token to be used to access any API that requires a valid auth token.

A demonstration of how these credentials can be retrieve and used to generate a JWT for a service, see `scripts/get-service-token.py`

## Using an existing role for authenticated user group
User groups with pre defined roles can be creating by providing the existing role's ARN. 
1. Set `DATA_MANAGERS_ROLE_ARN` in environment configuration
2. CDK deploy change and note `veda-auth-stack-<STAGE>.userpoolid` in output. It will include the deployment region and a UUID, for example `us-west-2:11111111-1111-1111-1111-111111111111`
3. Add a new statement to the role's trust policy in the AWS IAM console. Navigate to the desired role, choose `Trust Relationship` and select `edit`--be careful to preserve the existing trust statements when appending a new statement for this identity pool.

## Using an OIDC provider
To additionally deploy an OIDC provider (or use an existing one in the same account), set `OIDC_PROVIDER_URL` and `OIDC_THUMBPRINT` in environment configuration. For a github OIDC provider, the url is `token.actions.githubusercontent.com` and the thumbprint is `6938fd4d98bab03faadb97b34396831e3780aea1`.

### Example trust policy with appended statement for identity pool
In this example, the second object conditionally allows authenticated users from this identity pool to assume the role with a web identity. Two conditions should be applied: `StringEquals` to restrict the statement to this identity pool and `ForAnyValue:StringLike` to restrict to authenticated users.

The identity pool id is returned in the cloud formation output when this project is deployed. It can also be found in the AWS console by navigating to Cognito>Federated Identities, selecting the desired identity pool, and choosing 'Edit identity pool' to reveal the id.
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        },
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "us-west-2:11111111-1111-1111-1111-111111111111"
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            }
        }
    ]
}
```

## Obtaining AWS credentials
This project supplies a sample python [cognito-client](scripts/cognito_client.py) for using the veda-auth stack. The [temporary credentials notebook](scripts/temporary-credentials-example.ipynb) demonstrates how to use the deployed veda-auth stack to obtain AWS credentials via a password authentication flow.

### [PyPI cognito_client](https://pypi.org/project/cognito-client/)
A streamlined version of the client can be installed with `pip install cognito_client`, see usage instructions [here](https://github.com/developmentseed/cognito_client#use).

# License
This project is licensed under **Apache 2**, see the [LICENSE](LICENSE) file for more details.


## userpool

```python
cognito.UserPool(
    self,
    "userpool",
    user_pool_name=Stack.of(self).stack_name,
    removal_policy=RemovalPolicy.DESTROY,
    self_sign_up_enabled=False,
    sign_in_aliases={"username": True, "email": True},
    sign_in_case_sensitive=False,
    standard_attributes=cognito.StandardAttributes(
        email=cognito.StandardAttribute(required=True)
    ),
)
```

no mfa
email only
user name and email
don't enable self-registration
send email with cognito
userpool name: veda-auth-mcp-test
client: 
    auth_provider_client = self.add_programmatic_client(
        "cognito-identity-pool-auth-provider",
        name="Identity Pool Authentication Provider",
    )
    client = self.userpool.add_client(
        service_id,
        auth_flows=cognito.AuthFlow(user_password=True, admin_user_password=True),
        generate_secret=False,
        user_pool_client_name=name or service_id,
        # disable_o_auth=True,
    )

identity pool

```python
cognito_id_pool.IdentityPool(
    self,
    "identity_pool",
    identity_pool_name=f"{stack.stack_name} IdentityPool",
    authentication_providers=cognito_id_pool.IdentityPoolAuthenticationProviders(
        user_pools=[userpool_provider],
    ),
    role_mappings=[
        cognito_id_pool.IdentityPoolRoleMapping(
            provider_url=cognito_id_pool.IdentityPoolProviderUrl.user_pool(
                f"cognito-idp.{stack.region}.{stack.url_suffix}/"
                f"{userpool.user_pool_id}:{auth_provider_client.user_pool_client_id}"
            ),
            use_token=True,
            mapping_key="userpool",
        )
    ],
)
```

user access - authenticated access
authrnticated identity sources - amazon cognito user pool