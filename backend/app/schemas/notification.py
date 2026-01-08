from pydantic import BaseModel
from typing import Optional


class NotificationSettingsResponse(BaseModel):
    id: str
    user_id: str
    telegram_enabled: bool
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    email_enabled: bool
    email_address: Optional[str] = None
    level_1_enabled: bool
    level_2_enabled: bool
    level_3_enabled: bool
    
    class Config:
        from_attributes = True


class NotificationSettingsUpdate(BaseModel):
    telegram_enabled: Optional[bool] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    email_enabled: Optional[bool] = None
    email_address: Optional[str] = None
    level_1_enabled: Optional[bool] = None
    level_2_enabled: Optional[bool] = None
    level_3_enabled: Optional[bool] = None

