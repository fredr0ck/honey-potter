from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.schemas.user import UserResponse, Token
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_current_active_user
)
from app.core.config import settings
from app.models.user import User

router = APIRouter()


@router.post("/auth/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    if form_data.username != settings.admin_username or form_data.password != settings.admin_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.username == settings.admin_username).first()
    
    if not user:
        from app.core.security import get_password_hash
        from app.models.notification_settings import NotificationSettings
        
        user = User(
            username=settings.admin_username,
            email=None,
            hashed_password=get_password_hash(settings.admin_password),
            is_active=True,
            is_superuser=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
        notification_settings = NotificationSettings(
            user_id=user.id,
            telegram_enabled=True,
            level_1_enabled=False,
            level_2_enabled=True,
            level_3_enabled=True
        )
        db.add(notification_settings)
        db.commit()
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    return UserResponse(
        id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        created_at=current_user.created_at
    )

