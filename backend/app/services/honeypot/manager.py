import uuid
import asyncio
from sqlalchemy.orm import Session
from app.models.honeypot import HoneypotService, HoneypotStatus
from app.schemas.honeypot import HoneypotCreate, HoneypotUpdate
from app.services.docker.manager import DockerManager

class HoneypotManager:
    
    def __init__(self):
        self.docker_manager = DockerManager()
    
    async def get_all_honeypots(self, db: Session):
        return db.query(HoneypotService).all()
    
    async def get_honeypot(self, db: Session, honeypot_id: str):
        try:
            honeypot_uuid = uuid.UUID(honeypot_id)
        except ValueError:
            raise ValueError("Invalid honeypot ID format")
        
        return db.query(HoneypotService).filter(
            HoneypotService.id == honeypot_uuid
        ).first()
    
    async def create_honeypot(
        self, 
        db: Session, 
        honeypot_data: HoneypotCreate
    ):
        db_honeypot = HoneypotService(
            name=honeypot_data.name,
            description=honeypot_data.description,
            type=honeypot_data.type,
            port=honeypot_data.port,
            address=honeypot_data.address,
            config=honeypot_data.config,
            status=HoneypotStatus.STOPPED,
            notification_levels=honeypot_data.notification_levels
        )
        db.add(db_honeypot)
        db.commit()
        db.refresh(db_honeypot)
        
        return db_honeypot
    
    async def update_honeypot(
        self,
        db: Session,
        honeypot_id: str,
        update_data: HoneypotUpdate
    ):
        honeypot = await self.get_honeypot(db, honeypot_id)
        if not honeypot:
            raise ValueError("Honeypot not found")
        
        if honeypot.status == HoneypotStatus.RUNNING:
            if update_data.type is not None and update_data.type != honeypot.type:
                raise ValueError("Cannot change type while honeypot is running. Stop it first.")
            if update_data.port is not None and update_data.port != honeypot.port:
                raise ValueError("Cannot change port while honeypot is running. Stop it first.")
        
        if update_data.name is not None:
            honeypot.name = update_data.name
        if update_data.description is not None:
            honeypot.description = update_data.description
        if update_data.type is not None:
            honeypot.type = update_data.type
        if update_data.port is not None:
            honeypot.port = update_data.port
        if update_data.address is not None:
            honeypot.address = update_data.address
        if update_data.config is not None:
            honeypot.config = update_data.config
        if update_data.notification_levels is not None:
            honeypot.notification_levels = update_data.notification_levels
        
        db.commit()
        db.refresh(honeypot)
        return honeypot
    
    async def start_honeypot(self, db: Session, honeypot_id: str):
        honeypot = await self.get_honeypot(db, honeypot_id)
        if not honeypot:
            raise ValueError("Honeypot not found")
        
        if honeypot.status == HoneypotStatus.RUNNING:
            raise ValueError("Honeypot is already running")
        
        if honeypot.type == "http":
            try:
                container_name = f"honeypot-http-{honeypot.id}"
                
                container_id = await self.docker_manager.create_isolated_honeypot_container(
                    container_name=container_name,
                    honeypot_type="http",
                    port=honeypot.port,
                    service_id=str(honeypot.id),
                    config=honeypot.config
                )
                
                honeypot.docker_container_id = container_id
                honeypot.status = HoneypotStatus.RUNNING
                db.commit()
                return
            except Exception as e:
                honeypot.status = HoneypotStatus.ERROR
                db.commit()
                raise RuntimeError(f"Failed to start HTTP honeypot: {e}")
        
        if honeypot.type == "postgres":
            try:
                container_name = f"honeypot-postgres-{honeypot.id}"
                
                container_id = await self.docker_manager.create_isolated_honeypot_container(
                    container_name=container_name,
                    honeypot_type="postgres",
                    port=honeypot.port,
                    service_id=str(honeypot.id),
                    config=honeypot.config
                )
                
                honeypot.docker_container_id = container_id
                honeypot.status = HoneypotStatus.RUNNING
                db.commit()
                return
            except Exception as e:
                honeypot.status = HoneypotStatus.ERROR
                db.commit()
                raise RuntimeError(f"Failed to start PostgreSQL honeypot: {e}")
        
        if honeypot.docker_container_id:
            success = await self.docker_manager.start_container(honeypot.docker_container_id)
            if success:
                honeypot.status = HoneypotStatus.RUNNING
                db.commit()
                return
        
        container_name = f"honeypot-{honeypot.type}-{honeypot.id}"
        try:
            container_id = await self.docker_manager.create_honeypot_container(
                container_name=container_name,
                honeypot_type=honeypot.type,
                port=honeypot.port,
                config=honeypot.config
            )
            
            honeypot.docker_container_id = container_id
            honeypot.status = HoneypotStatus.RUNNING
            db.commit()
        except Exception as e:
            honeypot.status = HoneypotStatus.ERROR
            db.commit()
            raise RuntimeError(f"Failed to start honeypot container: {e}")
    
    async def stop_honeypot(self, db: Session, honeypot_id: str):
        honeypot = await self.get_honeypot(db, honeypot_id)
        if not honeypot:
            raise ValueError("Honeypot not found")
        
        if honeypot.type in ["http", "postgres"]:
            if honeypot.docker_container_id:
                success = await self.docker_manager.stop_container(honeypot.docker_container_id)
                if success:
                    honeypot.status = HoneypotStatus.STOPPED
                    db.commit()
                    return
                else:
                    raise RuntimeError(f"Failed to stop {honeypot.type} honeypot container")
            else:
                honeypot.status = HoneypotStatus.STOPPED
                db.commit()
                return
        
        if not honeypot.docker_container_id:
            honeypot.status = HoneypotStatus.STOPPED
            db.commit()
            return
        
        success = await self.docker_manager.stop_container(honeypot.docker_container_id)
        if success:
            honeypot.status = HoneypotStatus.STOPPED
            db.commit()
        else:
            raise RuntimeError("Failed to stop container")
    
    async def restart_honeypot(self, db: Session, honeypot_id: str):
        """Restart honeypot: stop and then start"""
        honeypot = await self.get_honeypot(db, honeypot_id)
        if not honeypot:
            raise ValueError("Honeypot not found")
        
        if honeypot.status == HoneypotStatus.RUNNING:
            await self.stop_honeypot(db, honeypot_id)
            db.refresh(honeypot)
        
        await self.start_honeypot(db, honeypot_id)
    
    async def delete_honeypot(self, db: Session, honeypot_id: str):
        honeypot = await self.get_honeypot(db, honeypot_id)
        if not honeypot:
            raise ValueError("Honeypot not found")
        
        if honeypot.status == HoneypotStatus.RUNNING:
            await self.stop_honeypot(db, honeypot_id)
        
        if honeypot.docker_container_id:
            await self.docker_manager.remove_container(honeypot.docker_container_id)
        
        from app.models.incident import Incident
        from app.models.event import Event
        
        incidents = db.query(Incident).filter(Incident.honeypot_id == honeypot.id).all()
        for incident in incidents:
            events = db.query(Event).filter(Event.incident_id == incident.id).all()
            for event in events:
                db.delete(event)
            db.delete(incident)
        
        events = db.query(Event).filter(Event.honeypot_id == honeypot.id).all()
        for event in events:
            db.delete(event)
        
        db.delete(honeypot)
        db.commit()
