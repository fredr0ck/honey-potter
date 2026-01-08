from sqlalchemy.orm import Session
from datetime import datetime
from app.models.credential import Credential


class CredentialValidator:
    
    async def check_credential(
        self,
        db: Session,
        username: str,
        password: str,
        service_type: str,
        source_ip: str
    ):
        credential = db.query(Credential).filter(
            Credential.username == username
        ).first()
        
        if not credential:
            return False, None
        
        if credential.password != password:
            return False, None
        
        if credential.used_at is None:
            credential.used_at = datetime.utcnow()
            db.commit()
            db.refresh(credential)
        
        return True, credential
    
    async def mark_as_used(
        self,
        db: Session,
        credential_id: str,
        source_ip: str = None
    ):
        credential = db.query(Credential).filter(
            Credential.id == credential_id
        ).first()
        
        if credential and credential.used_at is None:
            credential.used_at = datetime.utcnow()
            db.commit()
