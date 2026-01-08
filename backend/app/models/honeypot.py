from sqlalchemy import Column, String, Integer, JSON, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
import enum
from app.core.database import Base


class HoneypotStatus(str, enum.Enum):
    STOPPED = "stopped"
    RUNNING = "running"
    ERROR = "error"


class HoneypotService(Base):
    __tablename__ = "honeypot_services"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=True)  # Имя honeypot
    description = Column(String, nullable=True)  # Описание
    type = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    address = Column(String, default="0.0.0.0")
    status = Column(Enum(HoneypotStatus), default=HoneypotStatus.STOPPED)
    config = Column(JSON, default={})
    docker_container_id = Column(String, nullable=True)
    notification_levels = Column(JSON, default={"1": False, "2": True, "3": True})
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    def __repr__(self):
        return f"<HoneypotService(id={self.id}, type={self.type}, port={self.port}, status={self.status})>"
