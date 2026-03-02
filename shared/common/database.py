"""
Асинхронное подключение к PostgreSQL через SQLAlchemy 2.0.

get_async_engine — создаёт движок с пулом соединений.
get_async_session_factory — фабрика сессий (одна на сервис).
get_db_session — async generator для FastAPI Depends.
managed_session — context manager для кода вне FastAPI (bootstrap, cron).
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def get_async_engine(database_url: str, echo: bool = False) -> AsyncEngine:
    """
    pool_size=5 — хватит для наших нагрузок (до 10 пользователей).
    pool_pre_ping=True — проверяет соединение перед использованием,
    защищает от разрыва связи после простоя.
    """
    return create_async_engine(
        database_url,
        echo=echo,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )


def get_async_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """
    expire_on_commit=False — после commit объекты остаются
    доступны (нужно для возврата данных из endpoint).
    """
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def get_db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """
    Для FastAPI Depends.
    Открывает сессию → отдаёт в endpoint → закрывает.
    При исключении — rollback.
    """
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def managed_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """
    Для кода вне FastAPI: bootstrap admin, background tasks.
    Автоматический commit при успехе, rollback при ошибке.
    """
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()