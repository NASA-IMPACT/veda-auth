import pydantic


class Config(pydantic.BaseSettings):
    stage: str = "dev"
    owner: str = "alukach"
