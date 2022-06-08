#!/usr/bin/env python3
import aws_cdk as cdk

from infra.stack import AuthStack
from config import Config

config = Config()

app = cdk.App()
stack = AuthStack(
    app,
    f"veda-auth-stack-{config.stage}",
    tags={
        "Project": "veda",
        "Owner": config.owner,
        "Client": "nasa-impact",
        "Stack": config.stage,
    },
)

# Programmatic Clients
stack.add_programmatic_client("veda-sdk")

# Service-to-service Clients
stack.add_service_client("veda-stac-ingestion-registry")

app.synth()
