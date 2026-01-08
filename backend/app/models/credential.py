from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base


class Credential(Base):
    __tablename__ = "credentials"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service_id = Column(UUID(as_uuid=True), ForeignKey("honeypot_services.id"), nullable=True)  # Может быть None если еще не привязан
    service_type = Column(String, nullable=False)  # postgres, mysql, ssh, etc.
    username = Column(String, nullable=False, unique=True, index=True)  # Уникальный username для быстрого поиска
    password = Column(String, nullable=False)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    used_at = Column(DateTime(timezone=True), nullable=True)  # Когда был использован (Level 3!)
    meta_data = Column(String, nullable=True)  # JSON строка с метаданными (где размещен, etc.) - переименовано из metadata (зарезервировано в SQLAlchemy)
    
    service = relationship("HoneypotService", backref="credentials")
    
    def __repr__(self):
        return f"<Credential(id={self.id}, username={self.username}, used={self.used_at is not None})>"
