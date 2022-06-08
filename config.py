from getpass import getuser

import pydantic


class Config(pydantic.BaseSettings):
    stage: str = pydantic.Field(default_factory=getuser)
    owner: str = pydantic.Field(default_factory=getuser)
