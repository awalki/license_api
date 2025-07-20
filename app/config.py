from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )
    # Telegram settings
    admin_id: str
    webhook_url: str
    bot_token: str
    redis_url: str = "redis://localhost:6379"
    host: str = "0.0.0.0"
    port: int = 8000

    # Auth settings
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30


settings = Settings()  # type: ignore
