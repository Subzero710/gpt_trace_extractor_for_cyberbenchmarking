from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    storage_database_url: str = "postgresql+psycopg://gpt_traces:change-me@postgres:5432/gpt_traces"
    storage_host: str = "0.0.0.0"
    storage_port: int = 8080

settings = Settings()
