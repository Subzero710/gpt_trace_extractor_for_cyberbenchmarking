from __future__ import annotations

from urllib.parse import quote_plus

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    postgres_password: SecretStr
    storage_host: str = "0.0.0.0"
    storage_port: int = 8080

    @property
    def storage_database_url(self) -> str:
        password = quote_plus(self.postgres_password.get_secret_value())
        return (
            "postgresql+psycopg://gpt_traces:"
            f"{password}@postgres:5432/gpt_traces"
        )


settings = Settings()
