#!/usr/bin/env python3
import getpass
import json
from typing import TYPE_CHECKING

import boto3
import click
import pydantic
import requests


if TYPE_CHECKING:
    from mypy_boto3_cognito_idp.client import CognitoIdentityProviderClient
    from mypy_boto3_cognito_identity.client import CognitoIdentityClient
    from mypy_boto3_cognito_idp.type_defs import InitiateAuthResponseTypeDef


class Config(pydantic.BaseModel):
    cognito_domain: str
    client_id: str
    client_secret: str = pydantic.Field(repr=False)
    scope: str


class Creds(pydantic.BaseModel):
    access_token: str
    expires_in: int
    token_type: str


def get_token(config: Config) -> Creds:
    response = requests.post(
        f"{config.cognito_domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=(config.client_id, config.client_secret),
        data={
            "grant_type": "client_credentials",
            # A space-separated list of scopes to request for the generated access token.
            "scope": config.scope,
        },
    )
    try:
        response.raise_for_status()
    except Exception:
        print(response.text)
        raise
    return Creds(**response.json())


def get_cognito_service_details(stack_name: str, service_id: str) -> Config:
    client = boto3.client("secretsmanager")
    secret_id = f"{stack_name}/{service_id}"
    try:
        response = client.get_secret_value(SecretId=secret_id)
    except client.exceptions.ResourceNotFoundException:
        raise click.ClickException(
            f"Unable to find a secret for '{secret_id}'. "
            "\n\nHint: Check your stage and service id. Also, verify that the correct "
            "AWS_PROFILE is set on your environment."
        )
    return Config.parse_obj(json.loads(response["SecretString"]))


@click.command()
@click.option(
    "-s", "--stage", help="VEDA Auth Stage (e.g. dev, prod).", default=getpass.getuser
)
@click.option(
    "--stack-name-base",
    default="veda-auth-stack",
)
@click.option("--service-id", prompt="Service", help="Service that needs token.")
def get_token_via_client_credentials_flow(
    stage: str, service_id: str, stack_name_base: str = "veda-auth-stack"
) -> Config:
    """
    Get a JWT for a given service client registered with the VEDA Auth System.
    To be used for development purposes only.
    """
    cognito_details = get_cognito_service_details(
        f"{stack_name_base}-{stage}", service_id
    )
    credentials = get_token(cognito_details)
    click.echo(credentials.json())


if __name__ == "__main__":
    get_token_via_client_credentials_flow()
