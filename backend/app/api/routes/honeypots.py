from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.schemas.honeypot import HoneypotCreate, HoneypotResponse
from app.services.honeypot.manager import HoneypotManager
from app.core.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from typing import List
import uuid

router = APIRouter()
manager = HoneypotManager()


@router.get("/honeypots", response_model=list[HoneypotResponse])
async def get_honeypots(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    honeypots = await manager.get_all_honeypots(db)
    return [
        HoneypotResponse(
            id=str(hp.id),
            name=hp.name,
            description=hp.description,
            type=hp.type,
            port=hp.port,
            address=hp.address,
            status=hp.status.value if hasattr(hp.status, 'value') else str(hp.status),
            config=hp.config,
            docker_container_id=hp.docker_container_id,
            notification_levels=hp.notification_levels,
            created_at=hp.created_at,
            updated_at=hp.updated_at
        )
        for hp in honeypots
    ]


@router.post("/honeypots", response_model=HoneypotResponse)
async def create_honeypot(
    honeypot_data: HoneypotCreate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    honeypot = await manager.create_honeypot(db, honeypot_data)
    return HoneypotResponse(
        id=str(honeypot.id),
        name=honeypot.name,
        description=honeypot.description,
        type=honeypot.type,
        port=honeypot.port,
        address=honeypot.address,
        status=honeypot.status.value if hasattr(honeypot.status, 'value') else str(honeypot.status),
        config=honeypot.config,
        docker_container_id=honeypot.docker_container_id,
        notification_levels=honeypot.notification_levels,
        created_at=honeypot.created_at,
        updated_at=honeypot.updated_at
    )


@router.post("/honeypots/{honeypot_id}/start")
async def start_honeypot(
    honeypot_id: str, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        await manager.start_honeypot(db, honeypot_id)
        return {"status": "started", "honeypot_id": honeypot_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/honeypots/{honeypot_id}/stop")
async def stop_honeypot(
    honeypot_id: str, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        await manager.stop_honeypot(db, honeypot_id)
        return {"status": "stopped", "honeypot_id": honeypot_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/honeypots/{honeypot_id}")
async def delete_honeypot(
    honeypot_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    try:
        await manager.delete_honeypot(db, honeypot_id)
        return {"status": "deleted", "honeypot_id": honeypot_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/honeypots/bulk-delete", status_code=status.HTTP_200_OK)
async def bulk_delete_honeypots(
    honeypot_ids: List[str],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    from app.models.honeypot import HoneypotService
    
    if not honeypot_ids:
        raise HTTPException(status_code=400, detail="No honeypot IDs provided for deletion.")
    
    deleted_count = 0
    errors = []
    
    for honeypot_id_str in honeypot_ids:
        try:
            honeypot_uuid = uuid.UUID(honeypot_id_str)
            await manager.delete_honeypot(db, honeypot_id_str)
            deleted_count += 1
        except ValueError as e:
            errors.append(f"Invalid honeypot ID format: {honeypot_id_str}")
            db.rollback()
            continue
        except Exception as e:
            errors.append(f"Failed to delete honeypot {honeypot_id_str}: {str(e)}")
            db.rollback()
            continue
    if deleted_count > 0:
        try:
            db.commit()
        except Exception:
            db.rollback()
    
    result = {"status": "deleted", "deleted_count": deleted_count}
    if errors:
        result["errors"] = errors
    
    return result
