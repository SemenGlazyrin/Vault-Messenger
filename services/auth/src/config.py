"""
Конфигурация Auth-сервиса + типизированный AppState.
"""

import os
from dataclasses import dataclass

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, AsyncSession

from shared.common.base_config import BaseServiceConfig


class AuthConfig(BaseServiceConfig):
    def __init__(self):
        super().__init__()

        self.service_name = "auth"
        self.port = int(os.environ.get("PORT", "8001"))
        self.grpc_port = int(os.environ.get("GRPC_PORT", "50051"))

        # JWT
        self.jwt_secret: str = os.environ.get("JWT_SECRET", "CHANGE_ME")
        self.jwt_algorithm: str = os.environ.get("JWT_ALGORITHM", "HS256")
        self.jwt_access_token_expire_minutes: int = int(
            os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30")
        )
        self.jwt_refresh_token_expire_days: int = int(
            os.environ.get("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7")
        )

        # Admin bootstrap
        self.initial_admin_username: str | None = os.environ.get(
            "INITIAL_ADMIN_USERNAME"
        )
        self.initial_admin_password: str | None = os.environ.get(
            "INITIAL_ADMIN_PASSWORD"
        )
        self.initial_admin_panic_password: str | None = os.environ.get(
            "INITIAL_ADMIN_PANIC_PASSWORD"
        )

        # Lockout
        self.max_failed_login_attempts: int = int(
            os.environ.get("MAX_FAILED_LOGIN_ATTEMPTS", "5")
        )
        self.lockout_duration_minutes: int = int(
            os.environ.get("LOCKOUT_DURATION_MINUTES", "15")
        )

        # Epoch
        self.initial_epoch_key: str | None = os.environ.get("INITIAL_EPOCH_KEY")