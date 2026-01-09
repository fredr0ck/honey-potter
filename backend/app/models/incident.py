from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
import enum
from app.core.database import Base


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    honeypot_id = Column(UUID(as_uuid=True), ForeignKey("honeypot_services.id"), nullable=False)
    source_ip = Column(String, nullable=False, index=True)
    threat_level = Column(Integer, nullable=False)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.NEW)
    event_count = Column(Integer, default=1)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    details = Column(JSON, default={})
    
    honeypot = relationship("HoneypotService", backref="incidents")
    events = relationship("Event", back_populates="incident")
    
    def __repr__(self):
        return f"<Incident(id={self.id}, source_ip={self.source_ip}, threat_level={self.threat_level}, status={self.status})>"

