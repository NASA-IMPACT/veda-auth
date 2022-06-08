# VEDA Auth System

This codebase represents the Cognito-based authentication system used for the VEDA project.

Note: This is for setting up the user pools and managing applications, it is _not_ for managing users. Managing users should be instead done via AWS

## Expanding

The codebase intends to be expandable to meet VEDA's needs as the project grows. Currently, the stack exposes two methods to facilitate customization.

### `stack.add_programmatic_client(client_identifier)`

### `stack.add_service_client(client_identifier)`

Add a service that will be authenticating with the VEDA system. This utilizes the [`client_credentials` flow](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/), meaning that the credentials represent a _service_ rather than any particular _user_. Calling `.add_service_client()` with a unique identifier will create a [user pool app client](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html?icmpid=docs_cognito_console_help_panel) to represent this service. Credentials for the generated app client will be stored in an AWS SecretsManager Secret with an ID following the format of `{veda_auth_stack_name}/{service_identifier}`. The credentials can be retrieved by the related service and used to request an access token to be used to access any API that requires a valid auth token.

```py
from typing import Dict
from dataclasses import dataclass, field
import json

import boto3
import requests

@dataclass
class Config:
    cognito_domain: str
    client_id: str
    client_secret: str = field(repr=False)
    scope: str

@dataclass
class Creds:
    access_token: str
    expires_in: int
    token_type: str

def get_veda_service_config(
    stage: str,
    service_id: str,
    stack_name: str = 'veda-auth-stack'
) -> Config:
    """
    Get VEDA auth details for a given service.
    """
    secret_id = f'{stack_name}-{stage}/{service_id}'
    response = boto3.client('secretsmanager').get_secret_value(SecretId=secret_id)
    return Config(**json.loads(response['SecretString']))


def get_credentials(config: Config) -> Creds:
    response = requests.post(
        f"{config.cognito_domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=(config.client_id, config.client_secret),
        data={"grant_type": "client_credentials", "scope": config.scope}
    )
    try:
        response.raise_for_status()
    except Exception:
        print(response.text)
        raise
    return Creds(**response.json())


config = get_veda_service_config(
    stage='alukach',
    service_id='veda-workflows'
)
creds = get_credentials(config)
print(creds.access_token)
```
