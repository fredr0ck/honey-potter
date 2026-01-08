from sqlalchemy.orm import Session
from app.models.credential import Credential
from typing import Dict, List


class CredentialStorage:
    
    async def save_credential(
        self,
        db: Session,
        username: str,
        password: str,
        service_type: str,
        service_id: str = None,
        meta_data: str = None
    ) -> Credential:
        credential = Credential(
            username=username,
            password=password,
            service_type=service_type,
            service_id=service_id,
            meta_data=meta_data
        )
        db.add(credential)
        db.commit()
        db.refresh(credential)
        return credential
    
    async def save_multiple(
        self,
        db: Session,
        credentials: List[Dict[str, str]],
        service_id: str = None,
        meta_data: str = None
    ) -> List[Credential]:
        saved = []
        for cred in credentials:
            token_meta_data = cred.get('meta_data') or meta_data
            
            credential = await self.save_credential(
                db,
                cred['username'],
                cred['password'],
                cred['service_type'],
                service_id,
                token_meta_data
            )
            saved.append(credential)
        return saved
    
    async def get_by_username(self, db: Session, username: str) -> Credential:
        return db.query(Credential).filter(Credential.username == username).first()
    
    async def get_by_service(self, db: Session, service_id: str) -> List[Credential]:
        return db.query(Credential).filter(Credential.service_id == service_id).all()
