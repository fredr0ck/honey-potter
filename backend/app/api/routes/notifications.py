from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.notification import NotificationSettingsResponse, NotificationSettingsUpdate
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from app.models.notification_settings import NotificationSettings
import uuid

router = APIRouter()


@router.get("/notifications/settings", response_model=NotificationSettingsResponse)
async def get_notification_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    settings = db.query(NotificationSettings).filter(
        NotificationSettings.user_id == current_user.id
    ).first()
    
    if not settings:
        settings = NotificationSettings(
            user_id=current_user.id,
            telegram_enabled=True,
            level_1_enabled=False,
            level_2_enabled=True,
            level_3_enabled=True
        )
        db.add(settings)
        db.commit()
        db.refresh(settings)
    
    return NotificationSettingsResponse(
        id=str(settings.id),
        user_id=str(settings.user_id),
        telegram_enabled=settings.telegram_enabled,
        telegram_bot_token=settings.telegram_bot_token,
        telegram_chat_id=settings.telegram_chat_id,
        email_enabled=settings.email_enabled,
        email_address=settings.email_address,
        level_1_enabled=settings.level_1_enabled,
        level_2_enabled=settings.level_2_enabled,
        level_3_enabled=settings.level_3_enabled
    )


@router.put("/notifications/settings", response_model=NotificationSettingsResponse)
async def update_notification_settings(
    settings_update: NotificationSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    settings = db.query(NotificationSettings).filter(
        NotificationSettings.user_id == current_user.id
    ).first()
    
    if not settings:
        settings = NotificationSettings(user_id=current_user.id)
        db.add(settings)
    
    if settings_update.telegram_enabled is not None:
        settings.telegram_enabled = settings_update.telegram_enabled
    if settings_update.telegram_bot_token is not None:
        settings.telegram_bot_token = settings_update.telegram_bot_token
    if settings_update.telegram_chat_id is not None:
        settings.telegram_chat_id = settings_update.telegram_chat_id
    if settings_update.email_enabled is not None:
        settings.email_enabled = settings_update.email_enabled
    if settings_update.email_address is not None:
        settings.email_address = settings_update.email_address
    if settings_update.level_1_enabled is not None:
        settings.level_1_enabled = settings_update.level_1_enabled
    if settings_update.level_2_enabled is not None:
        settings.level_2_enabled = settings_update.level_2_enabled
    if settings_update.level_3_enabled is not None:
        settings.level_3_enabled = settings_update.level_3_enabled
    
    db.commit()
    db.refresh(settings)
    
    return NotificationSettingsResponse(
        id=str(settings.id),
        user_id=str(settings.user_id),
        telegram_enabled=settings.telegram_enabled,
        telegram_bot_token=settings.telegram_bot_token,
        telegram_chat_id=settings.telegram_chat_id,
        email_enabled=settings.email_enabled,
        email_address=settings.email_address,
        level_1_enabled=settings.level_1_enabled,
        level_2_enabled=settings.level_2_enabled,
        level_3_enabled=settings.level_3_enabled
    )

