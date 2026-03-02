"""
gRPC сервер Auth-сервиса.

Слушает на порту 50051 (grpc_port из конфига).
Использует сгенерированные из auth.proto классы.

Запускается параллельно с FastAPI HTTP-сервером из main.py.
"""

import logging
import grpc
from concurrent import futures

logger = logging.getLogger(__name__)

# Сгенерированные файлы появятся после make proto.
# Пока определяем структуру.
try:
    from grpc_generated import auth_pb2, auth_pb2_grpc

    class AuthServicer(auth_pb2_grpc.AuthServiceServicer):
        """gRPC servicer — делегирует вызовы в handlers."""

        def __init__(self, handlers):
            self.handlers = handlers

        async def ValidateToken(self, request, context):
            result = await self.handlers.validate_token(request.token)
            return auth_pb2.ValidateTokenResponse(
                valid=result["valid"],
                user_id=result["user_id"],
                username=result["username"],
                is_admin=result["is_admin"],
            )

        async def GetPublicKeys(self, request, context):
            keys = await self.handlers.get_public_keys(list(request.user_ids))
            key_infos = [
                auth_pb2.PublicKeyInfo(
                    user_id=k["user_id"],
                    signing_public_key=k["signing_public_key"],
                    x25519_public_key=k["x25519_public_key"],
                )
                for k in keys
            ]
            return auth_pb2.GetPublicKeysResponse(keys=key_infos)

    HAS_GRPC_GENERATED = True

except ImportError:
    HAS_GRPC_GENERATED = False
    logger.warning(
        "gRPC generated files not found. Run 'make proto' to generate. "
        "gRPC server will not start."
    )


async def start_grpc_server(handlers, port: int) -> grpc.aio.Server | None:
    """Запустить gRPC сервер. Возвращает server для graceful shutdown."""
    if not HAS_GRPC_GENERATED:
        logger.warning("Skipping gRPC server — no generated files")
        return None

    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(
        AuthServicer(handlers), server
    )
    server.add_insecure_port(f"[::]:{port}")
    await server.start()
    logger.info(f"gRPC server started on port {port}")
    return server