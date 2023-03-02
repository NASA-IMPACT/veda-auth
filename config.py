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
    project: str = pydantic.Field(
        description="Name of the project",
        default="veda",
    )
    delta_backend_external_role_arn: str = pydantic.Field(
        description="ARN of the delta-backend-staging-*-external-role deployed by",
        default="",
    )
    data_managers_role_arn: str = pydantic.Field(
        None,
        description="ARN of role to be assumed by authenticated users in data managers group.",
    )
