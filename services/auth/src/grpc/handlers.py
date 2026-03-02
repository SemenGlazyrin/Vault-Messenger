"""
gRPC обработчики — раздел 7.1.

ValidateToken — проверка JWT, возврат user info.
GetPublicKeys — публичные ключи по списку user_ids.

Вызываются другими сервисами:
- Gateway → ValidateToken (каждый запрос)
- Chat → GetPublicKeys (при создании чата)
"""

import uuid
import logging

from ..domain.repository import UserRepository
from ..security.jwt import JWTManager
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

logger = logging.getLogger(__name__)


class AuthGRPCHandlers:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        jwt_manager: JWTManager,
    ):
        self.session_factory = session_factory
        self.jwt_manager = jwt_manager

    async def validate_token(self, token: str) -> dict:
        """
        Проверяет JWT, возвращает user info.
        Используется Gateway при каждом запросе.
        """
        try:
            payload = self.jwt_manager.decode_access_token(token)
            return {
                "valid": True,
                "user_id": payload["sub"],
                "username": payload["username"],
                "is_admin": payload.get("is_admin", False),
            }
        except Exception:
            return {
                "valid": False,
                "user_id": "",
                "username": "",
                "is_admin": False,
            }

    async def get_public_keys(self, user_ids: list[str]) -> list[dict]:
        """
        Возвращает публичные ключи пользователей.
        Используется Chat-сервисом при создании чата.
        """
        uuids = [uuid.UUID(uid) for uid in user_ids]

        async with self.session_factory() as session:
            repo = UserRepository(session)
            users = await repo.get_public_keys(uuids)

        result = []
        for user in users:
            result.append({
                "user_id": str(user.id),
                "signing_public_key": user.signing_public_key or b"",
                "x25519_public_key": user.x25519_public_key or b"",
            })

        return result