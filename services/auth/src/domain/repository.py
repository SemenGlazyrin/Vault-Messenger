"""
Repository для таблицы users.

Отделяет SQL от бизнес-логики. service.py не знает
о SQLAlchemy — работает только через repository.
"""

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..domain.models import User


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        username: str,
        password_hash: str,
        panic_password_hash: str,
        is_admin: bool = False,
    ) -> User:
        user = User(
            username=username,
            password_hash=password_hash,
            panic_password_hash=panic_password_hash,
            is_admin=is_admin,
        )
        self.session.add(user)
        await self.session.flush()  # Получаем id без commit
        return user

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return await self.session.get(User, user_id)

    async def get_by_username(self, username: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def admin_exists(self) -> bool:
        """Для bootstrap — есть ли хоть один admin."""
        result = await self.session.execute(
            select(User.id).where(User.is_admin == True).limit(1)  # noqa: E712
        )
        return result.scalar_one_or_none() is not None

    async def update_public_keys(
        self,
        user_id: uuid.UUID,
        signing_public_key: bytes,
        x25519_public_key: bytes,
    ) -> None:
        """Загрузка ключей клиентом после первого входа."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                signing_public_key=signing_public_key,
                x25519_public_key=x25519_public_key,
            )
        )

    async def increment_failed_attempts(self, user_id: uuid.UUID) -> int:
        """Возвращает новое значение счётчика."""
        result = await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_attempts=User.failed_login_attempts + 1)
            .returning(User.failed_login_attempts)
        )
        return result.scalar_one()

    async def lock_account(self, user_id: uuid.UUID, until: datetime) -> None:
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(locked_until=until)
        )

    async def reset_failed_attempts(self, user_id: uuid.UUID) -> None:
        """Сброс после успешного входа."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(failed_login_attempts=0, locked_until=None)
        )

    async def get_all(self) -> list[User]:
        result = await self.session.execute(
            select(User).order_by(User.username)
        )
        return list(result.scalars().all())

    async def delete(self, user_id: uuid.UUID) -> bool:
        user = await self.get_by_id(user_id)
        if user is None:
            return False
        await self.session.delete(user)
        return True

    async def get_public_keys(self, user_ids: list[uuid.UUID]) -> list[User]:
        """Для gRPC GetPublicKeys — раздел 7.1."""
        result = await self.session.execute(
            select(User).where(User.id.in_(user_ids))
        )
        return list(result.scalars().all())