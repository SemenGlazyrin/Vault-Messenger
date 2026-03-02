FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    "sqlalchemy[asyncio]" \
    asyncpg \
    pydantic \
    pydantic-settings \
    "python-jose[cryptography]" \
    "passlib[bcrypt]" \
    bcrypt \
    alembic \
    PyNaCl \
    cryptography \
    grpcio \
    grpcio-tools \
    "redis[hiredis]"

FROM python:3.12-slim AS runtime

RUN groupadd -r vault && useradd -r -g vault vault

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages \
     /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# shared — общий код
COPY shared/ /app/shared/

# Код сервиса
COPY services/auth/src/ /app/src/
COPY services/auth/migrations/ /app/migrations/

# PYTHONPATH: src для кода сервиса, shared/common для config/database/logging
ENV PYTHONPATH="/app/src:/app/shared/common:/app/shared"

USER vault

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health')" || exit 1

EXPOSE 8001 50051

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]