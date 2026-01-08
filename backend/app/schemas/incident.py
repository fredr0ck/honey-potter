from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class IncidentResponse(BaseModel):
    id: str
    honeypot_id: str
    honeypot_name: Optional[str] = None  # Имя honeypot
    honeypot_type: Optional[str] = None  # Тип honeypot
    honeypot_port: Optional[int] = None  # Порт honeypot
    source_ip: str
    threat_level: int
    status: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    details: dict
    
    class Config:
        from_attributes = True


class IncidentUpdate(BaseModel):
    status: str


class IncidentListResponse(BaseModel):
    incidents: List[IncidentResponse]
    total: int

