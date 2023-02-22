from getpass import getuser

import pydantic


class Config(pydantic.BaseSettings):
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

    oidc_provider_url: str = pydantic.Field(
        "token.actions.githubusercontent.com",
        description="URL of OIDC provider to use for CI workers.",
    )

    oidc_thumbprint: str = pydantic.Field(
        "6938fd4d98bab03faadb97b34396831e3780aea1",
        description="Thumbprint of OIDC provider to use for CI workers.",
    )
