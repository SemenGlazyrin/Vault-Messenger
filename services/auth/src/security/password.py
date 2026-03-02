"""
Хеширование паролей — bcrypt с cost=12.
Раздел 3.1 документации.
"""

from passlib.context import CryptContext

_pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12
)


def hash_password(password: str) -> str:
    """Хешировать пароль. Возвращает bcrypt hash."""
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверить пароль. Constant-time comparison."""
    return _pwd_context.verify(plain_password, hashed_password)