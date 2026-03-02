"""
Pydantic-схемы — request/response модели.
По разделу 6.1 документации.
"""

import re
import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator


# === Auth (раздел 6.1) ===

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_key_setup: bool


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# === Key Setup ===

class KeySetupRequest(BaseModel):
    signing_public_key: str   # base64-encoded 32 bytes
    x25519_public_key: str    # base64-encoded 32 bytes


class KeySetupResponse(BaseModel):
    status: str = "keys_uploaded"


# === Session Init — раздел 3.8, 6.1 ===

class SessionInitRequest(BaseModel):
    ephemeral_public: str   # base64-encoded X25519 public key
    timestamp: int          # Unix timestamp
    request_id: str         # base64-encoded 16 bytes
    signature: str          # base64-encoded Ed25519 signature


class SessionInitResponse(BaseModel):
    server_ephemeral_public: str  # base64
    encrypted_epoch_key: str      # base64
    nonce: str                    # base64
    epoch_version: int


# === Admin — раздел 6.1 ===

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    panic_password: str = Field(..., min_length=8)
    is_admin: bool = False

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError(
                "Username: only letters, digits, underscores"
            )
        return v

    @field_validator("panic_password")
    @classmethod
    def panic_differs_from_password(cls, v: str, info: Any) -> str:
        password = info.data.get("password")
        if password and v == password:
            raise ValueError(
                "Panic password must differ from regular password"
            )
        return v


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    is_admin: bool
    has_keys: bool

    class Config:
        from_attributes = True