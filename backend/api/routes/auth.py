"""Authentication routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import CereberusConfig
from ...dependencies import get_app_config, get_current_user, get_db
from ...models.user import User
from ...utils.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "admin"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Authenticate user and return JWT token."""
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        secret_key=config.secret_key,
        algorithm=config.jwt_algorithm,
        expires_minutes=config.jwt_expiry_minutes,
    )

    return TokenResponse(access_token=token)


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Register a new user. For initial setup only."""
    # Check if username exists
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token(
        data={"sub": user.username, "role": user.role},
        secret_key=config.secret_key,
        algorithm=config.jwt_algorithm,
        expires_minutes=config.jwt_expiry_minutes,
    )

    return TokenResponse(access_token=token)


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user
