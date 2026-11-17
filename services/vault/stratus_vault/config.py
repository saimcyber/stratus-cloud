from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    database_url: str
    jwt_public_key_pem: str
    allowed_origins: list[str]
    demo_mode: bool
    max_object_bytes: int


@lru_cache
def get_settings() -> Settings:
    pem = os.getenv("JWT_PUBLIC_KEY", "")
    if not pem:
        raise RuntimeError("JWT_PUBLIC_KEY is required (base64 PEM of the KMS token key)")
    return Settings(
        database_url=os.getenv("VAULT_DATABASE_URL", "sqlite:///./vault.db"),
        jwt_public_key_pem=base64.b64decode(pem).decode(),
        allowed_origins=[o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()],
        demo_mode=os.getenv("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"},
        max_object_bytes=int(os.getenv("MAX_OBJECT_BYTES", str(10 * 1024 * 1024))),
    )
