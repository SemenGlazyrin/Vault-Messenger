"""
Типизированный AppState — убирает circular import
и даёт IDE автодополнение для app.state.
"""

from dataclasses import dataclass

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, AsyncSession

from config import AuthConfig
from security.jwt import JWTManager


@dataclass
class AppState:
    config: AuthConfig
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    jwt_manager: JWTManager
    epoch_key: bytes
    epoch_version: int


def get_app_state(request: Request) -> AppState:
    """Извлечь типизированный state из request."""
    return request.app.state._app_state  # type: ignore[attr-defined]