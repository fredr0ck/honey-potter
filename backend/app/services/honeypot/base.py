from abc import ABC, abstractmethod
from typing import Dict, Optional
import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.services.credentials.validator import CredentialValidator



class BaseHoneypot(ABC):
    
    def __init__(self, service_id: str, port: int, config: Dict):
        self.service_id = service_id
        self.port = port
        self.config = config
        self.is_running = False
        self.server = None
        self.validator = CredentialValidator()
        
    @abstractmethod
    async def start(self):
        pass
    
    @abstractmethod
    async def stop(self):
        pass
    
    @abstractmethod
    async def handle_connection(self, reader, writer):
        pass
    
    async def log_event(self, event_type: str, source_ip: str, details: Dict):
        from app.core.database import SessionLocal
        from app.services.events.processor import EventProcessor
        from app.services.alerts.notifier import AlertNotifier
        
        db = SessionLocal()
        try:
            processor = EventProcessor()
            event, incident = await processor.process_event(
                db=db,
                honeypot_id=str(self.service_id),
                event_type=event_type,
                level=details.get('level', 1),
                source_ip=source_ip,
                details=details,
                honeytoken_id=details.get('credential_id')
            )
        finally:
            db.close()
    
    async def check_credentials(
        self,
        username: str,
        password: str,
        source_ip: str
    ) -> tuple[bool, Optional[str]]:
        db = SessionLocal()
        try:
            service_type = self.__class__.__name__.lower().replace('honeypot', '')
            
            is_fake, credential = await self.validator.check_credential(
                db,
                username,
                password,
                service_type,
                source_ip
            )
            
            if is_fake and credential:
                await self.log_event('credential_reuse', source_ip, {
                    'level': 3,
                    'critical': True,
                    'username': username,
                    'credential_id': str(credential.id),
                    'service_type': service_type
                })
                return True, str(credential.id)
            else:
                await self.log_event('login_attempt', source_ip, {
                    'level': 2,
                    'username': username,
                    'service_type': service_type
                })
                return False, None
        finally:
            db.close()
