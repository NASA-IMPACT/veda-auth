#!/usr/bin/env python3
"""
The represents how a user can authenticate with a Cogntio application
within an interactive Python environment (e.g. Python Notebook)
"""

import os
import contextlib
import json
from typing import Any, Dict
from textwrap import dedent, indent

import boto3
import jwt
from pygments import highlight
from pygments.lexers import JsonLexer, PythonLexer
from pygments.formatters import TerminalFormatter

from veda_client import VedaAuthClient


# Allow user to skip prompts
FAST = os.environ.get("FAST")


class Text:
    BOLD = "\033[1m"
    ITALIC = "\x1B[3m"
    END = "\033[0m"
    HEADER = "\033[95m"


def bold(text: str) -> str:
    return f"{Text.BOLD}{text}{Text.END}"


def italic(text: str) -> str:
    return f"{Text.HEADER}{Text.ITALIC}{text}{Text.END}"


def prompt_continue(action="continue"):
    if FAST:
        return
    input(italic(f"press ↵ enter to {action}..."))
    print()


def print_dict(obj: Dict[Any, Any]):
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
            TerminalFormatter(bg="dark"),
        )
    )
    prompt_continue()


def print_code(code: str):
    print(
        "\n"
        + indent(
            highlight(
                dedent(code),
                PythonLexer(),
                TerminalFormatter(bg="dark"),
            ),
            prefix=">>> ",
        ),
    )
    prompt_continue("run code")


@contextlib.contextmanager
def test_call(test: str):
    try:
        yield
        print(bold(f"✅ Able to {test}"))
    except Exception as err:
        print(bold(f"❌ Failed to {test}, {err}"))
    prompt_continue()


if __name__ == "__main__":
    print_code(
        """
        # Setup client (get configuration)
        client = VedaAuthClient()"""
    )
    client = VedaAuthClient()

    print_code(
        """
        # Login (get password, send to Cognito)
        client.login()
        """
    )
    client.login()

    print(bold("\nSuccessfully logged in. Received Access Token and ID Token.\n"))
    prompt_continue()

    print_code(
        """
        print(client.access_token)
        """
    )
    print(client.access_token)
    prompt_continue()

    print_code(
        """
        import jwt
        # Examine the access token
        jwt.decode(client.access_token, options={"verify_signature": False})
        """
    )
    print_dict(
        jwt.decode(
            client.access_token,
            options={"verify_signature": False},
        )
    )

    print_code(
        """
        print(client.id_token)
        """
    )
    print(client.id_token)
    prompt_continue()

    print_code(
        """
        # Examine the ID Token
        jwt.decode(client.id_token, options={"verify_signature": False})
        """
    )
    print_dict(
        jwt.decode(
            client.id_token,
            options={"verify_signature": False},
        )
    )

    # Fetch AWS credentials
    print_code(
        """
        # Fetch AWS Credentials
        creds = client.get_aws_credentials()
        """
    )
    creds = client.get_aws_credentials()
    print_dict(creds)

    # Use credentials
    print_code(
        """
        import boto3
        # Setup s3 client to use returned credentials
        s3 = boto3.client(
            "s3",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
        )
        """
    )
    s3 = boto3.client(
        "s3",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
    )

    bucket = "veda-data-store-dev"
    key = "example-file.txt"

    with test_call(f"list s3://{bucket}"):
        print_code(
            f"""
            # List objects in bucket
            s3.list_objects_v2(Bucket={bucket!r})
            """
        )
        s3.list_objects_v2(
            Bucket=bucket,
        )

    with test_call(f"write s3://{bucket}/{key}"):
        print_code(
            f"""
            # Write to bucket
            s3.put_object(
                Bucket={bucket!r},
                Key={key!r},
                Body="🚀",
            )
            """
        )
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body="🚀",
        )

    with test_call(f"read s3://{bucket}/{key}"):
        print_code(
            f"""
            # Read from bucket
            s3.get_object(
                Bucket={bucket!r},
                Key={key!r},
            )
            """
        )
        s3.get_object(
            Bucket=bucket,
            Key=key,
        )
