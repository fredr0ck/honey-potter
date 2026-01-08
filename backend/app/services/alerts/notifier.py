from sqlalchemy.orm import Session
from typing import Dict, Optional
from app.models.notification_settings import NotificationSettings
from app.models.user import User
from app.services.alerts.telegram import TelegramNotifier


class AlertNotifier:
    
    def __init__(self):
        self.telegram = TelegramNotifier()
    
    async def notify_event(
        self,
        db: Session,
        level: int,
        event: Dict,
        incident: Optional[Dict] = None
    ):
        from app.core.config import settings
        
        user = db.query(User).filter(User.username == settings.admin_username).first()
        
        if not user or not user.is_active:
            print(f"[NOTIFIER] Admin user not found or inactive")
            return
        
        notification_settings = db.query(NotificationSettings).filter(
            NotificationSettings.user_id == user.id
        ).first()
        
        if not notification_settings:
            print(f"[NOTIFIER] Notification settings not found for admin user")
            return
        
        should_notify = False
        if level == 1:
            should_notify = notification_settings.level_1_enabled
        elif level == 2:
            should_notify = notification_settings.level_2_enabled
        elif level == 3:
            should_notify = notification_settings.level_3_enabled
        
        if not should_notify:
            print(f"[NOTIFIER] Level {level} notifications disabled in settings")
            return
        
        if not notification_settings.telegram_enabled:
            print(f"[NOTIFIER] Telegram notifications disabled")
            return
        
        if not notification_settings.telegram_bot_token or not notification_settings.telegram_chat_id:
            missing = []
            if not notification_settings.telegram_bot_token:
                missing.append("bot_token")
            if not notification_settings.telegram_chat_id:
                missing.append("chat_id")
            print(f"[NOTIFIER] Telegram enabled but missing: {', '.join(missing)}")
            return
        
        try:
            telegram_notifier = TelegramNotifier(bot_token=notification_settings.telegram_bot_token)
            success = await telegram_notifier.send_alert(
                notification_settings.telegram_chat_id,
                level,
                event,
                incident
            )
            if not success:
                print(f"[NOTIFIER] Failed to send Telegram notification")
            else:
                print(f"[NOTIFIER] Successfully sent notification (level {level})")
        except Exception as e:
            print(f"[NOTIFIER] Error sending Telegram notification: {e}")
