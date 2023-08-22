from getpass import getuser
from typing import Optional, Sequence

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

    oidc_provider_url: Optional[str] = pydantic.Field(
        None,
        description="URL of OIDC provider to use for CI workers.",
    )

    oidc_thumbprint: Optional[str] = pydantic.Field(
        None,
        description="Thumbprint of OIDC provider to use for CI workers.",
    )

    secret_role_access: Sequence[str] = pydantic.Field(
        [],
        description="Optional list of role ARNs with access to credential flow secrets"
    )