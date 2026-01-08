from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class EventResponse(BaseModel):
    id: str
    honeypot_id: str
    honeypot_name: Optional[str] = None  # Имя honeypot
    honeypot_type: Optional[str] = None  # Тип honeypot
    honeypot_port: Optional[int] = None  # Порт honeypot
    incident_id: Optional[str] = None
    event_type: str
    level: int
    source_ip: str
    honeytoken_id: Optional[str] = None
    timestamp: datetime
    details: dict
    
    class Config:
        from_attributes = True


class EventListResponse(BaseModel):
    events: List[EventResponse]
    total: int


class EventFilter(BaseModel):
    honeypot_id: Optional[str] = None
    level: Optional[int] = None
    source_ip: Optional[str] = None
    incident_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0
