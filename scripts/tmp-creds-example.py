#!/usr/bin/env python3
"""
The represents how a user can authenticate with a Cogntio application
within an interactive Python environment (e.g. Python Notebook)
"""

import json
import contextlib
from typing import Any, Dict

import boto3
import jwt
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

from veda_client import VedaAuthClient


def print_bold(text: str, **kwargs):
    BOLD = "\033[1m"
    END = "\033[0m"
    print(f"{BOLD}{text}{END}", **kwargs)


def prettyprint_dict(obj: Dict[Any, Any]):
    json_str = json.dumps(
        obj,
        indent=2,
        sort_keys=True,
        default=lambda d: d.isoformat(),
    )
    print(
        highlight(
            json_str,
            JsonLexer(),
            TerminalFormatter(),
        )
    )


@contextlib.contextmanager
def test_call(test: str):
    try:
        yield
        print_bold(f"✅ Able to {test}")
    except Exception as err:
        print_bold(f"❌ Unable to {test}, {err}")


if __name__ == "__main__":
    # Login
    print_bold("Authenticating with Cognito...")
    client = VedaAuthClient()
    client.login()

    print_bold("\nSuccessfully logged in. Received Auth Token and ID Token.\n")

    print_bold("Access Token (decoded):")
    prettyprint_dict(
        jwt.decode(
            client.access_token,
            options={"verify_signature": False},
        )
    )

    print_bold("ID Token (decoded):")
    prettyprint_dict(
        jwt.decode(
            client.id_token,
            options={"verify_signature": False},
        )
    )
    input("Press enter to fetch AWS Credentials.")

    # Fetch AWS credentials
    print_bold("Fetching AWS Credentials...")
    creds = client.get_aws_credentials()

    print_bold("Successfully fetched credentials. Credentials received:")
    prettyprint_dict(creds)

    input("Press enter to test credentials.")

    # Use credentials
    s3 = boto3.client(
        "s3",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
    )

    bucket = "veda-data-store-dev"
    key = "example-file.txt"

    with test_call(f"list s3://{bucket}"):
        s3.list_objects_v2(
            Bucket=bucket,
        )

    with test_call(f"write s3://{bucket}/{key}"):
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body="🚀",
        )

    with test_call(f"read s3://{bucket}/{key}"):
        s3.get_object(
            Bucket=bucket,
            Key=key,
        )
