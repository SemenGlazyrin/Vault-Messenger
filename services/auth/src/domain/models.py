"""
SQLAlchemy модели — таблица users.
Схема по разделу 5.1 документации.
"""

import uuid

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class User(Base):
    """
    Таблица users (раздел 5.1):

    id                   UUID PK
    username             VARCHAR(50) Unique
    password_hash        VARCHAR(255) bcrypt
    panic_password_hash  VARCHAR(255) bcrypt
    signing_public_key   BYTEA Ed25519 (32 bytes), nullable до key setup
    x25519_public_key    BYTEA X25519 (32 bytes), nullable до key setup
    is_admin             BOOLEAN
    locked_until         TIMESTAMP lockout
    failed_login_attempts INTEGER
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    username: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    panic_password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    signing_public_key: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    x25519_public_key: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    is_admin: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    locked_until: Mapped[None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    @property
    def has_keys(self) -> bool:
        """True если клиент загрузил публичные ключи."""
        return (
            self.signing_public_key is not None
            and self.x25519_public_key is not None
        )