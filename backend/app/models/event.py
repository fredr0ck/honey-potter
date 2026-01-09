from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Enum, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.core.database import Base


class Event(Base):
    __tablename__ = "events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    honeypot_id = Column(UUID(as_uuid=True), ForeignKey("honeypot_services.id"), nullable=False)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True)
    event_type = Column(String, nullable=False)
    level = Column(Integer, nullable=False)
    source_ip = Column(String, nullable=False, index=True)
    honeytoken_id = Column(UUID(as_uuid=True), ForeignKey("credentials.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    details = Column(JSON, default={})
    
    honeypot = relationship("HoneypotService", backref="events")
    incident = relationship("Incident", back_populates="events")
    honeytoken = relationship("Credential", backref="events")
    
    def __repr__(self):
        return f"<Event(id={self.id}, type={self.event_type}, level={self.level}, ip={self.source_ip})>"
