from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models.user import User

if CryptContext:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
else:
    pwd_context = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    if not pwd_context:
        raise RuntimeError("passlib not installed. Install with: pip install passlib[bcrypt]")
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Хеширование пароля"""
    if not pwd_context:
        raise RuntimeError("passlib not installed. Install with: pip install passlib[bcrypt]")
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создание JWT access токена"""
    if not jwt:
        raise RuntimeError("python-jose not installed. Install with: pip install python-jose[cryptography]")
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Создание JWT refresh токена"""
    if not jwt:
        raise RuntimeError("python-jose not installed. Install with: pip install python-jose[cryptography]")
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)  # Refresh токен на 7 дней
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Получение текущего пользователя из JWT токена"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not jwt:
        raise RuntimeError("python-jose not installed. Install with: pip install python-jose[cryptography]")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "access":
            raise credentials_exception
    except (JWTError, Exception):
        raise credentials_exception
    
    if username == settings.admin_username:
        from app.core.security import get_password_hash
        from app.models.notification_settings import NotificationSettings
        
        user = db.query(User).filter(User.username == settings.admin_username).first()
        
        if not user:
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
        
        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        
        notification_settings = db.query(NotificationSettings).filter(
            NotificationSettings.user_id == user.id
        ).first()
        
        if not notification_settings:
            notification_settings = NotificationSettings(
                user_id=user.id,
                telegram_enabled=True,
                level_1_enabled=False,
                level_2_enabled=True,
                level_3_enabled=True
            )
            db.add(notification_settings)
            db.commit()
        
        return user
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Получение активного пользователя"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
