from getpass import getuser
from typing import Optional

import os

import pydantic


class Config(pydantic.BaseSettings):
    # App name and deployment stage
    app_name: Optional[str] = pydantic.Field(
        "veda-auth-stack",
        description="Optional app name used to name stack and resources",
    )
    stage: str = pydantic.Field(
        description=" ".join(
            [
                "Stage of deployment (e.g. 'dev', 'prod').",
                "Used as suffix for stack name.",
                "Defaults to current username.",
            ]
        ),
        default_factory=getuser,
    )
    owner: str = pydantic.Field(
        description=" ".join(
            [
                "Name of primary contact for Cloudformation Stack.",
                "Used to tag generated resources",
                "Defaults to current username.",
            ]
        ),
        default_factory=getuser,
    )
    data_managers_role_arn: str = pydantic.Field(
        None,
        description="ARN of role to be assumed by authenticated users in data managers group.",
    )

    data_managers_group: bool = pydantic.Field(
        False,
        description="When true create data managers group (mcp-deploy refactor now requires additional control setting to enable creating this group).",
    )

    oidc_provider_url: Optional[str] = pydantic.Field(
        None,
        description="URL of OIDC provider to use for CI workers.",
    )

    oidc_thumbprint: Optional[str] = pydantic.Field(
        None,
        description="Thumbprint of OIDC provider to use for CI workers.",
    )

    permissions_boundary_policy_name: Optional[str] = pydantic.Field(
        None,
        description="Name of IAM policy to define stack permissions boundary",
    )

    # Since MCP doesn't allow creating identity pools, setting this as optional
    cognito_groups: Optional[bool] = pydantic.Field(
        False,
        description="whether to create cognito groups with bucket access permissions",
    )

    identity_pool_arn: Optional[str] = pydantic.Field(
        "",
        description="If creating cognito groups for access control, identity_pool id to associate",
    )

    user_pool_id: Optional[str] = pydantic.Field(
        "", description="The user pool id to use for user management"
    )

    bootstrap_qualifier: Optional[str] = pydantic.Field(
        None,
        description="Custom bootstrap qualifier override if not using a default installation of AWS CDK Toolkit to synthesize app.",
    )


app_settings = Config(_env_file=os.environ.get("ENV_FILE", ".env"))
