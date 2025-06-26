from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    secret_key: str
    admin_password: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30


# check if the SECRET_KEY is set
settings = Settings()
