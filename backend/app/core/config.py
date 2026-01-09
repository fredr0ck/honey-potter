from pydantic_settings import BaseSettings
from typing import Optional


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
    
    allowed_origins: list[str] = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
