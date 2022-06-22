#!/usr/bin/env python3
import getpass
import json

import boto3
import click
import pydantic
import requests


class Config(pydantic.BaseModel):
    cognito_domain: str
    client_id: str
    client_secret: str = pydantic.Field(repr=False)
    scope: str


class Creds(pydantic.BaseModel):
    access_token: str
    expires_in: int
    token_type: str


def get_credentials(config: Config) -> Creds:
    response = requests.post(
        f"{config.cognito_domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=(config.client_id, config.client_secret),
        data={"grant_type": "client_credentials", "scope": config.scope},
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
def get_veda_service_config(
    stage: str, service_id: str, stack_name_base: str = "veda-auth-stack"
) -> Config:
    """
    Get a JWT for a given service client registered with the VEDA Auth System.
    To be used for development purposes only.
    """
    cognito_details = get_cognito_service_details(
        f"{stack_name_base}-{stage}", service_id
    )
    credentials = get_credentials(cognito_details)
    click.echo(credentials.json())


if __name__ == "__main__":
    get_veda_service_config()
