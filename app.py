#!/usr/bin/env python3
import subprocess

from aws_cdk import App, Tags, DefaultStackSynthesizer

from infra.stack import AuthStack, BucketPermissions

from config import app_settings

app = App()

stack = AuthStack(
    app, 
    f"veda-auth-stack-{app_settings.stage}", 
    app_settings,
    synthesizer=DefaultStackSynthesizer(
        qualifier=app_settings.bootstrap_qualifier
    )
)

# Create an data managers group in user pool if data managers role is provided (legacy stack support)
if data_managers_role_arn := app_settings.data_managers_role_arn:
    stack.add_cognito_group_with_existing_role(
        "veda-data-store-managers",
        "Authenticated users assume read write veda data access role",
        role_arn=data_managers_role_arn,
    )

# Create Groups
if app_settings.cognito_groups:
    # Create a data managers group in user pool if data managers role is provided
    if data_managers_role_arn := app_settings.data_managers_role_arn:
        stack.add_cognito_group_with_existing_role(
            "veda-data-store-managers",
            "Authenticated users assume read write veda data access role",
            role_arn=data_managers_role_arn,
        )

    stack.add_cognito_group(
        "veda-staging-writers",
        "Users that have read/write-access to the VEDA store and staging datastore",
        {
            "veda-data-store-dev": BucketPermissions.read_write,
            "veda-data-store": BucketPermissions.read_write,
            "veda-data-store-staging": BucketPermissions.read_write,
        },
    )
    stack.add_cognito_group(
        "veda-writers",
        "Users that have read/write-access to the VEDA store",
        {
            "veda-data-store-dev": BucketPermissions.read_write,
            "veda-data-store": BucketPermissions.read_write,
        },
    )

    stack.add_cognito_group(
        "veda-staging-readers",
        "Users that have read-access to the VEDA store and staging data store",
        {
            "veda-data-store-dev": BucketPermissions.read_only,
            "veda-data-store": BucketPermissions.read_only,
            "veda-data-store-staging": BucketPermissions.read_only,
        },
    )
    # TODO: Should this be the default IAM role for the user group?
    stack.add_cognito_group(
        "veda-readers",
        "Users that have read-access to the VEDA store",
        {
            "veda-data-store": BucketPermissions.read_only,
        },
    )

# Generate a resource server (ie something to protect behind auth) with scopes
# (permissions that we can grant to users/services).
stac_registry_scopes = stack.add_resource_server(
    "veda-stac-ingestion-registry",
    supported_scopes={
        "stac:register": "Create STAC ingestions",
        "stac:cancel": "Cancel a STAC ingestion",
        "stac:list": "Cancel a STAC ingestion",
    },
)


# Generate a client for a service, specifying the permissions it will be granted.
# In this case, we want this client to be able to only register new STAC ingestions in
# the STAC ingestion registry service.
stack.add_service_client(
    "veda-workflows",
    scopes=[
        stac_registry_scopes["stac:register"],
    ],
)

# Generate an OIDC provider, allowing CI workers to assume roles in the account

oidc_thumbprint = app_settings.oidc_thumbprint
oidc_provider_url = app_settings.oidc_provider_url
if oidc_thumbprint and oidc_provider_url:
    stack.add_oidc_provider(
        f"veda-oidc-provider-{app_settings.stage}",
        oidc_provider_url,
        oidc_thumbprint,
    )

# Programmatic Clients
stack.add_programmatic_client("veda-sdk")

# Frontend Clients
# stack.add_frontend_client('veda-dashboard')

git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
try:
    git_tag = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
except subprocess.CalledProcessError:
    git_tag = "no-tag"

tags = {
    "Project": "veda",
    "Owner": app_settings.owner,
    "Client": "nasa-impact",
    "Stack": app_settings.stage,
    "GitCommit": git_sha,
    "GitTag": git_tag,
}

for key, value in tags.items():
    Tags.of(stack).add(key, value)

app.synth()
