"""
Базовый конфиг для всех сервисов.

Читает переменные окружения. Каждый сервис наследует
и добавляет свои поля (JWT_SECRET, MINIO_ENDPOINT, и т.д.).

Подключается через PYTHONPATH — не installable package.
"""

import os


class BaseServiceConfig:
    def __init__(self):
        self.database_url: str = os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://vault:vault@localhost:5432/vault",
        )
        self.redis_url: str = os.environ.get(
            "REDIS_URL",
            "redis://localhost:6379/0",
        )
        self.service_name: str = "unknown"
        self.debug: bool = os.environ.get("DEBUG", "false").lower() == "true"
        self.log_level: str = os.environ.get("LOG_LEVEL", "INFO")
        self.host: str = os.environ.get("HOST", "0.0.0.0")
        self.port: int = int(os.environ.get("PORT", "8000"))
        self.grpc_port: int = int(os.environ.get("GRPC_PORT", "50051"))