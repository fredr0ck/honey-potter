from pydantic import BaseModel
from typing import Optional, Dict
from datetime import datetime

class HoneypotCreate(BaseModel):
    name: Optional[str] = None  # Имя honeypot
    description: Optional[str] = None  # Описание
    type: str  # postgres, mysql, ssh, http
    port: int
    address: str = "0.0.0.0"  # Адрес для прослушивания
    config: Dict = {}  # Дополнительная конфигурация
    notification_levels: Dict[str, bool] = {"1": False, "2": True, "3": True}  # Какие уровни уведомлять

class HoneypotResponse(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    type: str
    port: int
    address: str
    status: str
    config: Dict
    docker_container_id: Optional[str] = None
    notification_levels: Dict[str, bool]
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True