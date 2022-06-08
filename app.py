#!/usr/bin/env python3
import os

import aws_cdk as cdk

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
    supported_scopes={
        "*": "Full Access",
        "register": "Create STAC ingestions",
    },
)


# Generate a client for a service, specifying the permissions it will be granted.
# In this case, we want this client to be able to only register new STAC ingestions in
# the STAC ingestion registry service.
stack.add_service_client("veda-workflows", scopes=[stac_registry_scopes["register"]])

# TODO:
# Programmatic Clients
# stack.add_programmatic_client("veda-sdk")
# Frontend Clients
# stack.add_frontend_client('veda-dashboard')

app.synth()
