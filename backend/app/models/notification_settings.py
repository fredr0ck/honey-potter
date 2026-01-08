from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base


class NotificationSettings(Base):
    __tablename__ = "notification_settings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, unique=True)
    
    telegram_enabled = Column(Boolean, default=True)
    telegram_bot_token = Column(String, nullable=True)
    telegram_chat_id = Column(String, nullable=True)
    
    email_enabled = Column(Boolean, default=False)
    email_address = Column(String, nullable=True)
    
    level_1_enabled = Column(Boolean, default=False)
    level_2_enabled = Column(Boolean, default=True)
    level_3_enabled = Column(Boolean, default=True)
    
    user = relationship("User", backref="notification_settings")
    
    def __repr__(self):
        return f"<NotificationSettings(user_id={self.user_id}, telegram={self.telegram_enabled})>"

