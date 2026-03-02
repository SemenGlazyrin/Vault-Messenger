"""
Точка входа Auth-сервиса.
"""

#TODO: проверить могу ли я запустить и продолжить работу

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, AsyncSession

from config import AuthConfig
from shared.common.database import get_async_engine, get_async_session_factory, managed_session
from shared.common.log import setup_logging, get_logger
from domain.models import Base
from domain.repository import UserRepository
from security.jwt import JWTManager
from security.password import hash_password
from api.router import router
from api.admin_router import admin_router
from grpc.server import start_grpc_server
from grpc.handlers import AuthGRPCHandlers
from app_state import AppState

logger = get_logger(__name__)


@dataclass
class AppState:
    """Типизированное хранилище состояния приложения."""
    config: AuthConfig
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: Redis
    jwt_manager: JWTManager
    epoch_key: bytes
    epoch_version: int


def get_app_state(request: Request) -> AppState:
    """Извлечь типизированный state из request."""
    return AppState._app_state  # type: ignore[attr-defined]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    config = AuthConfig()

    # 1. Logging
    setup_logging(config.service_name, config.log_level, config.debug)
    logger.info("Starting Auth service...")

    # 2. Database
    engine = get_async_engine(config.database_url, echo=config.debug)
    session_factory = get_async_session_factory(engine)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ensured")

    # 3. Redis
    redis = Redis.from_url(config.redis_url, decode_responses=False)
    try:
        await redis.ping()
        logger.info("Redis connected")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise

    # 4. JWT
    jwt_manager = JWTManager(
        secret=config.jwt_secret,
        algorithm=config.jwt_algorithm,
        access_token_expire_minutes=config.jwt_access_token_expire_minutes,
        refresh_token_expire_days=config.jwt_refresh_token_expire_days,
    )

    # 5. Epoch key
    if config.initial_epoch_key:
        epoch_key = bytes.fromhex(config.initial_epoch_key)
    else:
        epoch_key = os.urandom(32)
        logger.warning("No INITIAL_EPOCH_KEY set, generated random epoch key")
    epoch_version = 1

    # 6. Bootstrap admin
    await _bootstrap_admin(session_factory, config)

    # 7. Сохраняем типизированный state
    app_state = AppState(
        config=config,
        engine=engine,
        session_factory=session_factory,
        redis=redis,
        jwt_manager=jwt_manager,
        epoch_key=epoch_key,
        epoch_version=epoch_version,
    )
    app.state._app_state = app_state  # type: ignore[attr-defined]

    # 8. gRPC
    grpc_handlers = AuthGRPCHandlers(session_factory, jwt_manager)
    grpc_server = await start_grpc_server(grpc_handlers, config.grpc_port)

    logger.info(f"Auth service started — HTTP:{config.port} gRPC:{config.grpc_port}")

    yield

    # Shutdown
    logger.info("Shutting down Auth service...")
    if grpc_server:
        await grpc_server.stop(grace=5)
    await redis.close()
    await engine.dispose()
    logger.info("Auth service stopped")


async def _bootstrap_admin(session_factory, config: AuthConfig) -> None:
    """Раздел 4.6 — создание admin при первом запуске."""
    if not all([
        config.initial_admin_username,
        config.initial_admin_password,
        config.initial_admin_panic_password,
    ]):
        logger.warning("INITIAL_ADMIN_* not set, skipping bootstrap")
        return

    async with managed_session(session_factory) as session:
        repo = UserRepository(session)
        if await repo.admin_exists():
            logger.info("Admin exists, skipping bootstrap")
            return

        await repo.create(
            username=config.initial_admin_username,
            password_hash=hash_password(config.initial_admin_password),
            panic_password_hash=hash_password(config.initial_admin_panic_password),
            is_admin=True,
        )
        logger.info(f"Admin '{config.initial_admin_username}' created")


# === FastAPI app ===

app = FastAPI(
    title="Vault Auth Service",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/auth/docs",
    redoc_url=None,
)

app.include_router(router)
app.include_router(admin_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth"}