"""
Единый формат логов.

Production — JSON (для ELK / Grafana Loki).
Debug — human-readable.

setup_logging() вызывается один раз в main.py каждого сервиса.
get_logger() — получить logger для конкретного модуля.
"""

import logging
import sys
import json
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Structured JSON для production."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": getattr(record, "service", "unknown"),
            "message": record.getMessage(),
            "logger": record.name,
        }
        for key in ("request_id", "user_id", "chat_id", "action"):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value
        if record.exc_info and record.exc_info[2] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


class DevFormatter(logging.Formatter):
    """Читаемый формат для разработки."""

    def format(self, record: logging.LogRecord) -> str:
        service = getattr(record, "service", "?")
        return f"[{record.levelname:8}] {service} | {record.getMessage()}"


def setup_logging(
    service_name: str,
    level: str = "INFO",
    debug: bool = False,
) -> None:
    """
    Вызывается один раз при старте сервиса.
    Устанавливает формат и уровень для всех logger-ов.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(DevFormatter() if debug else JSONFormatter())
    root.addHandler(handler)

    # Добавляем service_name в каждую запись автоматически
    old_factory = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = old_factory(*args, **kwargs)
        record.service = service_name  # type: ignore[attr-defined]
        return record

    logging.setLogRecordFactory(factory)

    # Уменьшаем шум от библиотек
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if debug else logging.WARNING
    )


def get_logger(name: str) -> logging.Logger:
    """Получить logger для модуля. Обычно: get_logger(__name__)"""
    return logging.getLogger(name)