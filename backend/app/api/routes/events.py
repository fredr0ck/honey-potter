from fastapi import APIRouter, Depends, HTTPException, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import and_
from app.schemas.event import EventResponse, EventListResponse, EventFilter
from app.schemas.incident import IncidentResponse, IncidentListResponse, IncidentUpdate
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.core.config import settings
from app.models.user import User
from app.models.event import Event
from app.models.incident import Incident, IncidentStatus
from app.services.events.processor import EventProcessor
from app.services.credentials.validator import CredentialValidator
import uuid
import json
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

router = APIRouter()


class InternalEventRequest(BaseModel):                                                                                                                                                                                                          
    honeypot_id: str
    event_type: str
    level: int
    source_ip: str
    details: dict
    honeytoken_check: Optional[dict] = None


def check_honeytoken_in_request_text(request_text: str, db: Session) -> tuple[Optional[str], int]:
    if not request_text:
        return None, 1
    
    from app.models.credential import Credential
    from sqlalchemy import or_
    
    credentials = db.query(Credential).all()
    
    if not credentials:
        return None, 1
    
    request_text_lower = request_text.lower()
    
    for cred in credentials:
        username = cred.username
        password = cred.password
        
        username_found = False
        password_found = False
        
        if username:
            username_found = username.lower() in request_text_lower
        if password:
            password_found = password.lower() in request_text_lower
        
        if username_found or password_found:
            if cred.used_at is None:
                from datetime import datetime
                cred.used_at = datetime.utcnow()
                db.commit()
            print(f"[EVENTS] ✅ Honeytoken detected! username='{username[:30] if username else 'N/A'}' (found: {username_found}), password='{password[:20] if password else 'N/A'}...' (found: {password_found})")
            return str(cred.id), 3
    
    return None, 1


@router.post("/events/internal")
async def receive_internal_event(
    event_data: InternalEventRequest,
    db: Session = Depends(get_db),
    x_honeypot_token: Optional[str] = Header(None, alias="X-Honeypot-Token")
):
    expected_token = settings.secret_key[:16]
    if x_honeypot_token != expected_token:
        raise HTTPException(status_code=401, detail="Invalid honeypot token")
    
    request_text = event_data.details.get('request_text', '')
    if not request_text:
        full_url = event_data.details.get('full_url', '')
        path = event_data.details.get('path', '')
        query_string = event_data.details.get('query_string', '')
        query_params = event_data.details.get('query', {})
        body = event_data.details.get('body', '')
        headers_str = json.dumps(event_data.details.get('headers', {}))
        query_params_str = json.dumps(query_params) if query_params else ''
        request_text = f"{full_url}\n{path}\n{query_string}\n{query_params_str}\n{headers_str}\n{body}"
    
    honeytoken_id, detected_level = check_honeytoken_in_request_text(request_text, db)
    
    honeytoken_username = None
    if honeytoken_id:
        from app.models.credential import Credential
        credential = db.query(Credential).filter(Credential.id == uuid.UUID(honeytoken_id)).first()
        if credential:
            honeytoken_username = credential.username
            event_data.details['honeytoken_username'] = honeytoken_username
    
    if honeytoken_id and event_data.level < detected_level:
        event_data.level = detected_level
    
    processor = EventProcessor()
    event, incident = await processor.process_event(
        db=db,
        honeypot_id=event_data.honeypot_id,
        event_type=event_data.event_type,
        level=event_data.level,
        source_ip=event_data.source_ip,
        details=event_data.details,
        honeytoken_id=honeytoken_id
    )
    
    return {"status": "ok", "event_id": str(event.id)}


@router.get("/events", response_model=EventListResponse)
async def get_events(
    honeypot_id: Optional[str] = Query(None),
    level: Optional[int] = Query(None),
    source_ip: Optional[str] = Query(None),
    incident_id: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = db.query(Event)
    
    if honeypot_id:
        try:
            honeypot_uuid = uuid.UUID(honeypot_id)
            query = query.filter(Event.honeypot_id == honeypot_uuid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid honeypot_id format")
    
    if level:
        query = query.filter(Event.level == level)
    
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    
    if incident_id:
        try:
            incident_uuid = uuid.UUID(incident_id)
            query = query.filter(Event.incident_id == incident_uuid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid incident_id format")
    
    total = query.count()
    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()
    
    from app.models.honeypot import HoneypotService
    
    event_responses = []
    for e in events:
        honeypot = db.query(HoneypotService).filter(HoneypotService.id == e.honeypot_id).first()
        event_responses.append(
            EventResponse(
                id=str(e.id),
                honeypot_id=str(e.honeypot_id),
                honeypot_name=honeypot.name if honeypot else None,
                honeypot_type=honeypot.type if honeypot else None,
                honeypot_port=honeypot.port if honeypot else None,
                incident_id=str(e.incident_id) if e.incident_id else None,
                event_type=e.event_type,
                level=e.level,
                source_ip=e.source_ip,
                honeytoken_id=str(e.honeytoken_id) if e.honeytoken_id else None,
                timestamp=e.timestamp,
                details=e.details
            )
        )
    
    return EventListResponse(events=event_responses, total=total)


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        event_uuid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid event_id format")
    
    event = db.query(Event).filter(Event.id == event_uuid).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    from app.models.honeypot import HoneypotService
    honeypot = db.query(HoneypotService).filter(HoneypotService.id == event.honeypot_id).first()
    
    return EventResponse(
        id=str(event.id),
        honeypot_id=str(event.honeypot_id),
        honeypot_name=honeypot.name if honeypot else None,
        honeypot_type=honeypot.type if honeypot else None,
        honeypot_port=honeypot.port if honeypot else None,
        incident_id=str(event.incident_id) if event.incident_id else None,
        event_type=event.event_type,
        level=event.level,
        source_ip=event.source_ip,
        honeytoken_id=str(event.honeytoken_id) if event.honeytoken_id else None,
        timestamp=event.timestamp,
        details=event.details
    )


@router.get("/incidents", response_model=IncidentListResponse)
async def get_incidents(
    honeypot_id: Optional[str] = Query(None),
    threat_level: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = db.query(Incident)
    
    if honeypot_id:
        try:
            honeypot_uuid = uuid.UUID(honeypot_id)
            query = query.filter(Incident.honeypot_id == honeypot_uuid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid honeypot_id format")
    
    if threat_level:
        query = query.filter(Incident.threat_level == threat_level)
    
    if status:
        try:
            status_enum = IncidentStatus(status)
            query = query.filter(Incident.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")
    
    total = query.count()
    incidents = query.order_by(Incident.last_seen.desc()).offset(offset).limit(limit).all()
    
    from app.models.honeypot import HoneypotService
    
    incident_responses = []
    for i in incidents:
        honeypot = db.query(HoneypotService).filter(HoneypotService.id == i.honeypot_id).first()
        incident_responses.append(
            IncidentResponse(
                id=str(i.id),
                honeypot_id=str(i.honeypot_id),
                honeypot_name=honeypot.name if honeypot else None,
                honeypot_type=honeypot.type if honeypot else None,
                honeypot_port=honeypot.port if honeypot else None,
                source_ip=i.source_ip,
                threat_level=i.threat_level,
                status=i.status.value,
                event_count=i.event_count,
                first_seen=i.first_seen,
                last_seen=i.last_seen,
                details=i.details
            )
        )
    
    return IncidentListResponse(incidents=incident_responses, total=total)


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident_id format")
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    from app.models.honeypot import HoneypotService
    honeypot = db.query(HoneypotService).filter(HoneypotService.id == incident.honeypot_id).first()
    
    return IncidentResponse(
        id=str(incident.id),
        honeypot_id=str(incident.honeypot_id),
        honeypot_name=honeypot.name if honeypot else None,
        honeypot_type=honeypot.type if honeypot else None,
        honeypot_port=honeypot.port if honeypot else None,
        source_ip=incident.source_ip,
        threat_level=incident.threat_level,
        status=incident.status.value,
        event_count=incident.event_count,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        details=incident.details
    )


@router.put("/incidents/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    status_update: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        incident_uuid = uuid.UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident_id format")
    
    incident = db.query(Incident).filter(Incident.id == incident_uuid).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    try:
        incident.status = IncidentStatus(status_update.status)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status value")
    
    db.commit()
    db.refresh(incident)
    
    from app.models.honeypot import HoneypotService
    honeypot = db.query(HoneypotService).filter(HoneypotService.id == incident.honeypot_id).first()
    
    return IncidentResponse(
        id=str(incident.id),
        honeypot_id=str(incident.honeypot_id),
        honeypot_name=honeypot.name if honeypot else None,
        honeypot_type=honeypot.type if honeypot else None,
        honeypot_port=honeypot.port if honeypot else None,
        source_ip=incident.source_ip,
        threat_level=incident.threat_level,
        status=incident.status.value,
        event_count=incident.event_count,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        details=incident.details
    )
