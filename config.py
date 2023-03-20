from getpass import getuser
from typing import List, Optional

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
    project: str = pydantic.Field(
        description="Name of the project",
        default="veda",
    )
    veda_backend_external_role_arn: Optional[str] = pydantic.Field(
        description=(
            "ARN of the veda-backend-staging-*-external-role"
            " deployed by veda-stac-ingestor"
        ),
    )
    data_managers_role_arn: Optional[str] = pydantic.Field(
        description=(
            "ARN of role to be assumed by authenticated users in data managers group."
        ),
    )

    # Optional list of buckets/s3 prefixes to be granted access to
    access_role_buckets: List[str] = []

    oidc_provider_url: Optional[str] = pydantic.Field(
        None,
        description="URL of OIDC provider to use for CI workers.",
    )

    oidc_thumbprint: Optional[str] = pydantic.Field(
        None,
        description="Thumbprint of OIDC provider to use for CI workers.",
    )
