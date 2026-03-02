"""
HTTP API аутентификации — раздел 6.1.
"""

import base64
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from schemas import (
    KeySetupRequest,
    KeySetupResponse,
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    SessionInitRequest,
    SessionInitResponse,
)
from ..domain.repository import UserRepository
from ..domain.service import AuthenticationError, AuthService, ValidationError, NotFoundError
from ..security.ephemeral import EphemeralExchange, EphemeralExchangeError
from ..app_state import AppState, get_app_state

router = APIRouter(prefix="/auth", tags=["auth"])


# === Dependencies ===

async def get_db_session(request: Request):
    """DB-сессия per-request."""
    state = get_app_state(request)
    session = state.session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_auth_service(
    request: Request,
    session=Depends(get_db_session),
) -> AuthService:
    state = get_app_state(request)
    repo = UserRepository(session)
    return AuthService(
        user_repo=repo,
        jwt_manager=state.jwt_manager,
        max_failed_attempts=state.config.max_failed_login_attempts,
        lockout_minutes=state.config.lockout_duration_minutes,
    )


def get_current_user_id(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    token = authorization[7:]
    state = get_app_state(request)
    try:
        payload = state.jwt_manager.decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_admin(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = authorization[7:]
    state = get_app_state(request)
    try:
        payload = state.jwt_manager.decode_access_token(token)
        if not payload.get("is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        return payload["sub"]
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# === Endpoints ===

@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    service: AuthService = Depends(get_auth_service),
):
    try:
        result = await service.login(
            username=body.username,
            password=body.password,
        )
        return LoginResponse(**result)
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(
    body: RefreshRequest,
    service: AuthService = Depends(get_auth_service),
):
    try:
        result = await service.refresh_token(body.refresh_token)
        return RefreshResponse(**result)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/keys", response_model=KeySetupResponse)
async def setup_keys(
    body: KeySetupRequest,
    user_id: str = Depends(get_current_user_id),
    service: AuthService = Depends(get_auth_service),
):
    try:
        signing_key = base64.b64decode(body.signing_public_key)
        x25519_key = base64.b64decode(body.x25519_public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    try:
        await service.setup_keys(
            user_id=uuid.UUID(user_id),
            signing_public_key=signing_key,
            x25519_public_key=x25519_key,
        )
        return KeySetupResponse()
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=e.message)
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=e.message)


@router.post("/session/init", response_model=SessionInitResponse)
async def session_init(
    body: SessionInitRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    session=Depends(get_db_session),
):
    state = get_app_state(request)

    repo = UserRepository(session)
    user = await repo.get_by_id(uuid.UUID(user_id))
    if user is None or not user.has_keys:
        raise HTTPException(status_code=400, detail="Keys not set up")

    try:
        client_eph_pub = base64.b64decode(body.ephemeral_public)
        request_id = base64.b64decode(body.request_id)
        signature = base64.b64decode(body.signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding")

    ephemeral = EphemeralExchange(
        redis=state.redis,
        epoch_key=state.epoch_key,
        epoch_version=state.epoch_version,
    )

    try:
        result = await ephemeral.process(
            client_ephemeral_public=client_eph_pub,
            timestamp=body.timestamp,
            request_id=request_id,
            signature=signature,
            user_signing_public_key=user.signing_public_key,
        )
    except EphemeralExchangeError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return SessionInitResponse(
        server_ephemeral_public=base64.b64encode(result["server_ephemeral_public"]).decode(),
        encrypted_epoch_key=base64.b64encode(result["encrypted_epoch_key"]).decode(),
        nonce=base64.b64encode(result["nonce"]).decode(),
        epoch_version=result["epoch_version"],
    )