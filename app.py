#!/usr/bin/env python3
import os

import aws_cdk as cdk
from aws_cdk.aws_cognito import ResourceServerScope

from infra.stack import AuthStack
from config import Config

config = Config(_env_file=os.environ.get("ENV_FILE", ".env"))

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

# Generate a resource server (ie something to protect behind auth) with scopes
# (permissions that we can grant to users/services).
stac_registry_scopes = stack.add_resource_server(
    "veda-stac-ingestion-registry",
    scopes={"*": ResourceServerScope(scope_name="*", scope_description="Full Access")},
)


# Generate a client for a service, specifying the permissions it will be granted
stack.add_service_client("veda-workflows", scopes=[stac_registry_scopes["*"]])

# TODO:
# Programmatic Clients
# stack.add_programmatic_client("veda-sdk")
# Frontend Clients
# stack.add_frontend_client('veda-dashboard')

app.synth()
