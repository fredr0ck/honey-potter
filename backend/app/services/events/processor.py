from sqlalchemy.orm import Session
from datetime import datetime
from app.models.event import Event
from app.models.incident import Incident, IncidentStatus
from app.models.honeypot import HoneypotService
from typing import Dict, Optional
import uuid


class EventProcessor:
    
    async def process_event(
        self,
        db: Session,
        honeypot_id: str,
        event_type: str,
        level: int,
        source_ip: str,
        details: Dict,
        honeytoken_id: Optional[str] = None
    ) -> tuple[Event, Optional[Incident]]:
        honeypot_uuid = uuid.UUID(honeypot_id)
        
        event = Event(
            honeypot_id=honeypot_uuid,
            event_type=event_type,
            level=level,
            source_ip=source_ip,
            honeytoken_id=uuid.UUID(honeytoken_id) if honeytoken_id else None,
            details=details
        )
        db.add(event)
        db.flush()
        
        incident = await self._get_or_create_incident(
            db, honeypot_uuid, source_ip, level
        )
        
        if incident:
            event.incident_id = incident.id
            incident.event_count += 1
            incident.last_seen = datetime.utcnow()
            if level > incident.threat_level:
                incident.threat_level = level
                if level == 3 and incident.status == IncidentStatus.RESOLVED:
                    incident.status = IncidentStatus.NEW
        
        db.commit()
        db.refresh(event)
        
        from app.services.alerts.notifier import AlertNotifier
        from app.models.honeypot import HoneypotService
        
        honeypot = db.query(HoneypotService).filter(HoneypotService.id == honeypot_uuid).first()
        
        honeytoken_username = None
        if honeytoken_id:
            from app.models.credential import Credential
            credential = db.query(Credential).filter(Credential.id == uuid.UUID(honeytoken_id)).first()
            if credential:
                honeytoken_username = credential.username
        
        notifier = AlertNotifier()
        await notifier.notify_event(
            db=db,
            level=event.level,
            event={
                'honeypot_type': honeypot.type if honeypot else 'unknown',
                'honeypot_name': honeypot.name if honeypot else None,
                'source_ip': source_ip,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event_type,
                'honeytoken_username': honeytoken_username or details.get('honeytoken_username'),
                'details': details
            },
            incident={
                'id': str(incident.id) if incident else None,
                'event_count': incident.event_count if incident else 1
            } if incident else None
        )
        
        return event, incident
    
    async def _get_or_create_incident(
        self,
        db: Session,
        honeypot_id: uuid.UUID,
        source_ip: str,
        level: int
    ) -> Optional[Incident]:
        incident = db.query(Incident).filter(
            Incident.honeypot_id == honeypot_id,
            Incident.source_ip == source_ip,
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING])
        ).first()
        
        if incident:
            return incident
        
        incident = Incident(
            honeypot_id=honeypot_id,
            source_ip=source_ip,
            threat_level=level,
            status=IncidentStatus.NEW,
            event_count=0,
            details={}
        )
        db.add(incident)
        db.flush()
        
        return incident
