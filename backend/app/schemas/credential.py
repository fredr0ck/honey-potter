from pydantic import BaseModel
from typing import Optional, Dict, List
from datetime import datetime


class CredentialItem(BaseModel):
    username: Optional[str] = None
    meta_data: Optional[str] = None


class CredentialCreate(BaseModel):
    service_type: str
    count: int = 1
    service_id: Optional[str] = None
    items: Optional[List[CredentialItem]] = None


class CredentialResponse(BaseModel):
    id: str
    username: str
    password: str
    service_type: str
    service_id: Optional[str] = None
    generated_at: datetime
    used_at: Optional[datetime] = None
    meta_data: Optional[str] = None
    
    class Config:
        from_attributes = True


class CredentialListResponse(BaseModel):
    credentials: list[CredentialResponse]
    total: int
