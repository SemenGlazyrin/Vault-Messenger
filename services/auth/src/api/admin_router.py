"""
Admin API — управление пользователями.
Раздел 6.1 документации.
Все эндпоинты требуют admin JWT.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from router import get_auth_service, require_admin
from schemas import CreateUserRequest, UserResponse
from ..domain.service import AuthService, ConflictError, ValidationError

admin_router = APIRouter(prefix="/admin", tags=["admin"])


@admin_router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    body: CreateUserRequest,
    admin_id: str = Depends(require_admin),
    service: AuthService = Depends(get_auth_service),
):
    """Создание пользователя — только admin."""
    try:
        result = await service.create_user(
            admin_id=uuid.UUID(admin_id),
            username=body.username,
            password=body.password,
            panic_password=body.panic_password,
            is_admin=body.is_admin,
        )
        return UserResponse(**result)
    except ConflictError as e:
        raise HTTPException(status_code=409, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=e.message)