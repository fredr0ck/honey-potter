from pydantic_settings import BaseSettings
from typing import Optional
import os


def get_allowed_origins() -> list[str]:
    origins_env = os.environ.get("ALLOWED_ORIGINS", "").strip()
    if origins_env:
        return [origin.strip() for origin in origins_env.split(",") if origin.strip()]
    return ["*"]


class Settings(BaseSettings):
    app_name: str = "Honey Potter"
    debug: bool = False
    
    database_url: str = "postgresql://honeypot:honeypot_password@postgres:5432/honeypot_db"
    
    redis_url: str = "redis://redis:6379/0"
    
    secret_key: str = "change-this-secret-key-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    api_key: Optional[str] = None
    
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    
    admin_username: str = "admin"
    admin_password: str = "admin"
    
    docker_socket: str = "unix://var/run/docker.sock"
    
    @property
    def allowed_origins(self) -> list[str]:
        return get_allowed_origins()
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
