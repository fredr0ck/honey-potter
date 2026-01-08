from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.credential import CredentialCreate, CredentialResponse, CredentialListResponse
from app.services.credentials.generator import CredentialGenerator
from app.services.credentials.storage import CredentialStorage
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
import uuid

router = APIRouter()
generator = CredentialGenerator()
storage = CredentialStorage()


@router.post("/credentials/generate", response_model=CredentialListResponse)
async def generate_credentials(
    cred_data: CredentialCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    service_id_uuid = None
    if cred_data.service_id:
        try:
            service_id_uuid = uuid.UUID(cred_data.service_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid service_id format")
    
    items = None
    count = cred_data.count
    
    if cred_data.items:
        items = [
            {
                'username': item.username,
                'meta_data': item.meta_data
            }
            for item in cred_data.items
            ]
        count = len(items)
    else:
        if count < 1:
            raise HTTPException(status_code=400, detail="Count must be at least 1")
        
        if count > 100:
            raise HTTPException(status_code=400, detail="Count cannot exceed 100")
    
    generated_creds = generator.generate_multiple(
        cred_data.service_type,
        count,
        items
    )
    
    saved_creds = await storage.save_multiple(
        db,
        generated_creds,
        service_id_uuid,
        None
    )
    
    cred_responses = [
        CredentialResponse(
            id=str(cred.id),
            username=cred.username,
            password=cred.password,
            service_type=cred.service_type,
            service_id=str(cred.service_id) if cred.service_id else None,
            generated_at=cred.generated_at,
            used_at=cred.used_at,
            meta_data=cred.meta_data
        )
        for cred in saved_creds
    ]
    
    return CredentialListResponse(
        credentials=cred_responses,
        total=len(cred_responses)
    )


@router.get("/credentials", response_model=CredentialListResponse)
async def get_credentials(
    service_type: str = None,
    service_id: str = None,
    used_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from app.models.credential import Credential
    
    query = db.query(Credential)
    
    if service_type:
        query = query.filter(Credential.service_type == service_type)
    
    if service_id:
        try:
            service_id_uuid = uuid.UUID(service_id)
            query = query.filter(Credential.service_id == service_id_uuid)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid service_id format")
    
    if used_only:
        query = query.filter(Credential.used_at.isnot(None))
    
    creds = query.all()
    
    cred_responses = [
        CredentialResponse(
            id=str(cred.id),
            username=cred.username,
            password=cred.password,
            service_type=cred.service_type,
            service_id=str(cred.service_id) if cred.service_id else None,
            generated_at=cred.generated_at,
            used_at=cred.used_at,
            meta_data=cred.meta_data
        )
        for cred in creds
    ]
    
    return CredentialListResponse(
        credentials=cred_responses,
        total=len(cred_responses)
    )


@router.get("/credentials/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from app.models.credential import Credential
    
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid credential_id format")
    
    cred = db.query(Credential).filter(Credential.id == cred_uuid).first()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    return CredentialResponse(
        id=str(cred.id),
        username=cred.username,
        password=cred.password,
        service_type=cred.service_type,
        service_id=str(cred.service_id) if cred.service_id else None,
        generated_at=cred.generated_at,
        used_at=cred.used_at,
        meta_data=cred.meta_data
    )


@router.delete("/credentials/{credential_id}")
async def delete_credential(
    credential_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from app.models.credential import Credential
    
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid credential_id format")
    
    cred = db.query(Credential).filter(Credential.id == cred_uuid).first()
    
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")
    
    db.delete(cred)
    db.commit()
    
    return {"status": "deleted", "credential_id": credential_id}


@router.post("/credentials/bulk-delete")
async def bulk_delete_credentials(
    credential_ids: list[str],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from app.models.credential import Credential
    
    if not credential_ids:
        raise HTTPException(status_code=400, detail="No credential IDs provided")
    
    if len(credential_ids) > 100:
        raise HTTPException(status_code=400, detail="Cannot delete more than 100 credentials at once")
    
    cred_uuids = []
    for cred_id in credential_ids:
        try:
            cred_uuids.append(uuid.UUID(cred_id))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid credential_id format: {cred_id}")
    
    deleted_count = db.query(Credential).filter(Credential.id.in_(cred_uuids)).delete(synchronize_session=False)
    db.commit()
    
    return {"status": "deleted", "count": deleted_count}
