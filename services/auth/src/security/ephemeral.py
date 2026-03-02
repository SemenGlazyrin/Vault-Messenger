"""
Ephemeral key exchange — раздел 3.8 документации.

Клиент отправляет:
- ephemeral X25519 public key
- timestamp
- request_id (16 bytes)
- Ed25519 подпись всего выше

Сервер:
1. Проверяет timestamp (±5 минут)
2. Проверяет replay (request_id в Redis, TTL 600с)
3. Проверяет подпись через signing_public_key пользователя
4. Генерирует свой ephemeral X25519
5. Вычисляет shared_secret через ECDH
6. Шифрует epoch_key через AES-GCM с ключом из HKDF(shared_secret)
7. Уничтожает server ephemeral private key
8. Возвращает server ephemeral public + encrypted epoch_key
"""

import os
import time
import logging

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class EphemeralExchangeError(Exception):
    """Ошибка ephemeral exchange."""
    pass


class ReplayDetectedError(EphemeralExchangeError):
    pass


class InvalidTimestampError(EphemeralExchangeError):
    pass


class InvalidSignatureError(EphemeralExchangeError):
    pass


class EphemeralExchange:
    """
    Обработка POST /auth/session/init.

    Нужен Redis для replay protection и epoch_key + epoch_version
    из конфига или хранилища.
    """

    TIMESTAMP_TOLERANCE = 300  # ±5 минут
    REPLAY_TTL = 600  # 10 минут — request_id живёт в Redis

    def __init__(self, redis: Redis, epoch_key: bytes, epoch_version: int):
        self.redis = redis
        self.epoch_key = epoch_key
        self.epoch_version = epoch_version

    async def process(
            self,
            client_ephemeral_public: bytes,
            timestamp: int,
            request_id: bytes,
            signature: bytes,
            user_signing_public_key: bytes,
    ) -> dict:
        """
        Возвращает dict с server_ephemeral_public, encrypted_epoch_key,
        nonce, epoch_version.
        """
        # 1. Timestamp check
        now = int(time.time())
        if abs(now - timestamp) > self.TIMESTAMP_TOLERANCE:
            raise InvalidTimestampError(
                f"Timestamp drift: {abs(now - timestamp)}s"
            )

        # 2. Replay check
        replay_key = f"ephemeral_replay:{request_id.hex()}"
        already_seen = await self.redis.set(
            replay_key, b"1", ex=self.REPLAY_TTL, nx=True
        )
        if not already_seen:
            raise ReplayDetectedError("request_id already used")

        # 3. Signature verification
        signed_data = (
                client_ephemeral_public
                + timestamp.to_bytes(8, "big")
                + request_id
        )
        try:
            verify_key = VerifyKey(user_signing_public_key)
            verify_key.verify(signed_data, signature)
        except BadSignatureError:
            raise InvalidSignatureError("Ed25519 signature verification failed")

        # 4. Server ephemeral key pair
        server_eph_private = X25519PrivateKey.generate()
        server_eph_public = server_eph_private.public_key()

        # 5. ECDH → shared secret
        client_pub = X25519PublicKey.from_public_bytes(client_ephemeral_public)
        shared_secret = server_eph_private.exchange(client_pub)

        # 6. HKDF → encryption key
        encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"epoch_key_encryption_v1",
        ).derive(shared_secret)

        # 7. Encrypt epoch_key
        nonce = os.urandom(12)
        aesgcm = AESGCM(encryption_key)
        encrypted_epoch = aesgcm.encrypt(nonce, self.epoch_key, None)

        # 8. Serialize server public key
        server_pub_bytes = server_eph_public.public_bytes_raw()

        # 9. Уничтожаем приватный ключ (Python GC, но явно удаляем ссылку)
        del server_eph_private

        logger.info("Ephemeral exchange completed", extra={"action": "ephemeral_exchange"})

        return {
            "server_ephemeral_public": server_pub_bytes,
            "encrypted_epoch_key": encrypted_epoch,
            "nonce": nonce,
            "epoch_version": self.epoch_version,
        }