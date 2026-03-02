"""
JWT токены.

Access token — 30 мин, содержит user_id, username, is_admin.
Refresh token — 7 дней, содержит только user_id.

Поле type ("access"/"refresh") предотвращает использование
refresh token как access и наоборот.

jti (JWT ID) — уникальный ID токена для логов и будущего revocation.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt


class JWTManager:
    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ):
        self.secret = secret
        self.algorithm = algorithm
        self.access_expire = timedelta(minutes=access_token_expire_minutes)
        self.refresh_expire = timedelta(days=refresh_token_expire_days)

    def create_access_token(
        self,
        user_id: uuid.UUID,
        username: str,
        is_admin: bool = False,
    ) -> str:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": str(user_id),
            "username": username,
            "is_admin": is_admin,
            "type": "access",
            "exp": now + self.access_expire,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: uuid.UUID) -> str:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": str(user_id),
            "type": "refresh",
            "exp": now + self.refresh_expire,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)

    def decode_token(self, token: str) -> dict[str, Any]:
        """Декодирует и проверяет подпись + expiration."""
        return jwt.decode(token, self.secret, algorithms=[self.algorithm])

    def decode_access_token(self, token: str) -> dict[str, Any]:
        payload = self.decode_token(token)
        if payload.get("type") != "access":
            raise JWTError("Not an access token")
        return payload

    def decode_refresh_token(self, token: str) -> dict[str, Any]:
        payload = self.decode_token(token)
        if payload.get("type") != "refresh":
            raise JWTError("Not a refresh token")
        return payload