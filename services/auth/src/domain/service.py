"""
Бизнес-логика аутентификации.

Login flow (раздел 2.1, 6.1):
1. Найти пользователя
2. Проверить lockout
3. Проверить panic password — ПЕРВЫМ (constant timing)
4. Проверить обычный пароль
5. При panic — 401 + side effect (уничтожение)
6. При неверном пароле — инкремент счётчика, возможный lockout
7. При успехе — сброс счётчика, выдача токенов

Panic password (раздел 2.1):
- Записывается в audit как login_failed (ADR-009)
- Ответ идентичен неверному паролю
- Оба bcrypt.verify выполняются всегда (constant timing)
"""

import uuid
import logging
from datetime import datetime, timedelta, timezone

from ..domain.repository import UserRepository
from ..security.jwt import JWTManager
from ..security.password import hash_password, verify_password

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Неверные credentials или panic."""
    pass


class ConflictError(Exception):
    """Дубликат (username уже существует)."""
    def __init__(self, message: str = "Conflict"):
        self.message = message
        super().__init__(message)


class ValidationError(Exception):
    """Невалидные входные данные."""
    def __init__(self, message: str = "Validation error"):
        self.message = message
        super().__init__(message)


class NotFoundError(Exception):
    """Ресурс не найден."""
    def __init__(self, resource: str = "Resource", identifier: str = ""):
        self.message = f"{resource} '{identifier}' not found"
        super().__init__(self.message)


class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        jwt_manager: JWTManager,
        max_failed_attempts: int = 5,
        lockout_minutes: int = 15,
    ):
        self.user_repo = user_repo
        self.jwt = jwt_manager
        self.max_failed_attempts = max_failed_attempts
        self.lockout_minutes = lockout_minutes

    async def login(self, username: str, password: str) -> dict:
        """
        Возвращает dict с access_token, refresh_token, token_type,
        requires_key_setup. Бросает AuthenticationError при неудаче.
        """
        user = await self.user_repo.get_by_username(username)

        if user is None:
            # Пользователь не найден — dummy verify для constant timing.
            # Атакующий не должен узнать, существует ли username.
            verify_password(password, hash_password("dummy"))
            logger.info(
                "Login failed: user not found",
                extra={"action": "login_failed"},
            )
            raise AuthenticationError()

        # Lockout
        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.info(
                "Login failed: account locked",
                extra={"user_id": str(user.id), "action": "login_locked"},
            )
            raise AuthenticationError()

        # Проверяем ОБА пароля ВСЕГДА — constant timing.
        # Если проверять panic только при !is_valid, атакующий
        # увидит разницу во времени ответа.
        is_panic = verify_password(password, user.panic_password_hash)
        is_valid = verify_password(password, user.password_hash)

        if is_panic:
            # Panic! Ответ и лог неотличимы от неверного пароля (ADR-009).
            logger.info(
                "Login failed",
                extra={"user_id": str(user.id), "action": "login_failed"},
            )
            # TODO: trigger panic — epoch rotation, data purge
            raise AuthenticationError()

        if not is_valid:
            attempts = await self.user_repo.increment_failed_attempts(user.id)

            if attempts >= self.max_failed_attempts:
                lock_until = datetime.now(timezone.utc) + timedelta(
                    minutes=self.lockout_minutes
                )
                await self.user_repo.lock_account(user.id, lock_until)
                logger.warning(
                    "Account locked due to failed attempts",
                    extra={"user_id": str(user.id), "action": "account_locked"},
                )

            logger.info(
                "Login failed",
                extra={"user_id": str(user.id), "action": "login_failed"},
            )
            raise AuthenticationError()

        # Успех — сброс счётчика
        await self.user_repo.reset_failed_attempts(user.id)

        access_token = self.jwt.create_access_token(
            user_id=user.id,
            username=user.username,
            is_admin=user.is_admin,
        )
        refresh_token = self.jwt.create_refresh_token(user_id=user.id)

        logger.info(
            "Login successful",
            extra={"user_id": str(user.id), "action": "login_success"},
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "requires_key_setup": not user.has_keys,
        }

    async def refresh_token(self, refresh_token_str: str) -> dict:
        """Выдать новый access token по refresh token."""
        payload = self.jwt.decode_refresh_token(refresh_token_str)
        user_id = uuid.UUID(payload["sub"])

        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise AuthenticationError()

        access_token = self.jwt.create_access_token(
            user_id=user.id,
            username=user.username,
            is_admin=user.is_admin,
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
        }

    async def create_user(
        self,
        admin_id: uuid.UUID,
        username: str,
        password: str,
        panic_password: str,
        is_admin: bool = False,
    ) -> dict:
        """Создание пользователя администратором (раздел 6.1)."""
        existing = await self.user_repo.get_by_username(username)
        if existing:
            raise ConflictError(f"User '{username}' already exists")

        if password == panic_password:
            raise ValidationError(
                "Panic password must differ from regular password"
            )

        user = await self.user_repo.create(
            username=username,
            password_hash=hash_password(password),
            panic_password_hash=hash_password(panic_password),
            is_admin=is_admin,
        )

        logger.info(
            "User created",
            extra={
                "user_id": str(user.id),
                "action": "user_created",
                "actor_id": str(admin_id),
            },
        )

        return {
            "id": user.id,
            "username": user.username,
            "is_admin": user.is_admin,
            "has_keys": user.has_keys,
        }

    async def setup_keys(
        self,
        user_id: uuid.UUID,
        signing_public_key: bytes,
        x25519_public_key: bytes,
    ) -> None:
        """
        Загрузка публичных ключей клиентом (раздел 3.2).
        Ключи генерируются на клиенте. Сервер хранит только public.
        """
        user = await self.user_repo.get_by_id(user_id)
        if user is None:
            raise NotFoundError("User", str(user_id))

        if len(signing_public_key) != 32:
            raise ValidationError("signing_public_key must be 32 bytes")
        if len(x25519_public_key) != 32:
            raise ValidationError("x25519_public_key must be 32 bytes")

        await self.user_repo.update_public_keys(
            user_id=user_id,
            signing_public_key=signing_public_key,
            x25519_public_key=x25519_public_key,
        )

        logger.info(
            "Keys uploaded",
            extra={"user_id": str(user_id), "action": "keys_setup"},
        )