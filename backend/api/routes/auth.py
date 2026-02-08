"""Authentication routes with password strength validation and rate limiting."""

import hashlib
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...config import CereberusConfig
from ...dependencies import get_app_config, get_current_user, get_db
from ...models.user import User
from ...utils.rate_limiter import RateLimiter
from ...utils.security import create_access_token, decode_access_token, hash_password, verify_password

# Try to import RBAC role permissions for JWT enrichment
try:
    from ...auth.rbac import DEFAULT_ROLES
except ImportError:
    DEFAULT_ROLES = {}

router = APIRouter(prefix="/auth", tags=["auth"])

# Rate limiter: 5 login attempts per 5-minute window per IP
_login_limiter = RateLimiter(max_attempts=5, window_seconds=300)

# Burn list — maps token SHA-256 hash to expiry timestamp
_burn_list: dict[str, float] = {}


def is_token_burned(token: str) -> bool:
    """Check if a token has been burned (revoked). Also prunes up to 50 expired entries."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()

    # Prune up to 50 expired entries
    pruned = 0
    expired_keys = []
    for k, exp in _burn_list.items():
        if exp < now:
            expired_keys.append(k)
            pruned += 1
            if pruned >= 50:
                break
    for k in expired_keys:
        _burn_list.pop(k, None)

    return token_hash in _burn_list and _burn_list[token_hash] >= now


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _validate_password_strength(password: str, min_length: int = 12) -> None:
    """Validate password meets strength requirements."""
    errors = []
    if len(password) < min_length:
        errors.append(f"at least {min_length} characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a digit")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        errors.append("a special character")

    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Password must contain {', '.join(errors)}",
        )


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
    must_change_password: bool = False


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Authenticate user and return JWT token."""
    client_ip = _get_client_ip(request)

    # Check rate limit
    if _login_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        _login_limiter.record_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Successful login — reset rate limit for this IP
    _login_limiter.reset(client_ip)

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    # Build permissions list from user role
    role_def = DEFAULT_ROLES.get(user.role, {})
    permissions = role_def.get("permissions", [])

    token = create_access_token(
        data={"sub": user.username, "role": user.role, "permissions": permissions},
        secret_key=config.secret_key,
        algorithm=config.jwt_algorithm,
        expires_minutes=config.jwt_expiry_minutes,
    )

    return TokenResponse(
        access_token=token,
        must_change_password=getattr(user, "must_change_password", False),
    )


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Register a new user. For initial setup only."""
    # Validate password strength
    _validate_password_strength(body.password, min_length=config.min_password_length)

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

    role_def = DEFAULT_ROLES.get(user.role, {})
    permissions = role_def.get("permissions", [])

    token = create_access_token(
        data={"sub": user.username, "role": user.role, "permissions": permissions},
        secret_key=config.secret_key,
        algorithm=config.jwt_algorithm,
        expires_minutes=config.jwt_expiry_minutes,
    )

    return TokenResponse(access_token=token)


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return current_user


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Refresh JWT token with updated permissions."""
    result = await db.execute(
        select(User).where(User.username == current_user["sub"])
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role_def = DEFAULT_ROLES.get(user.role, {})
    permissions = role_def.get("permissions", [])

    token = create_access_token(
        data={"sub": user.username, "role": user.role, "permissions": permissions},
        secret_key=config.secret_key,
        algorithm=config.jwt_algorithm,
        expires_minutes=config.jwt_expiry_minutes,
    )

    return TokenResponse(access_token=token)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    config: CereberusConfig = Depends(get_app_config),
):
    """Change the current user's password."""
    result = await db.execute(
        select(User).where(User.username == current_user["sub"])
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    _validate_password_strength(body.new_password, min_length=config.min_password_length)

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    await db.commit()

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    config: CereberusConfig = Depends(get_app_config),
):
    """Logout — burn the current token so it cannot be reused."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:]
    else:
        raise HTTPException(status_code=400, detail="No bearer token found")

    # Decode token to get expiry
    payload = decode_access_token(raw_token, config.secret_key, config.jwt_algorithm)
    if payload and "exp" in payload:
        expiry = float(payload["exp"])
    else:
        # Default: burn for 1 hour
        expiry = time.time() + 3600

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    _burn_list[token_hash] = expiry

    return {"message": "Burn notice issued"}
