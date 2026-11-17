from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    root_kek_b64: str
    jwt_private_key_pem: str
    allowed_origins: list[str]
    demo_mode: bool
    demo_password: str
    token_ttl_minutes: int


@lru_cache
def get_settings() -> Settings:
    root = os.getenv("ROOT_KEK", "")
    if not root:
        raise RuntimeError("ROOT_KEK is required (base64-encoded 32 random bytes). Run scripts/gen_secrets.py")
    if len(base64.b64decode(root)) != 32:
        raise RuntimeError("ROOT_KEK must decode to exactly 32 bytes (AES-256)")

    pem = os.getenv("JWT_PRIVATE_KEY", "")
    if not pem:
        raise RuntimeError("JWT_PRIVATE_KEY is required (base64 PEM Ed25519). Run scripts/gen_secrets.py")

    origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
    return Settings(
        database_url=os.getenv("KMS_DATABASE_URL", "sqlite:///./kms.db"),
        root_kek_b64=root,
        jwt_private_key_pem=base64.b64decode(pem).decode(),
        allowed_origins=origins,
        demo_mode=_bool("DEMO_MODE", True),
        demo_password=os.getenv("DEMO_PASSWORD", "stratus-demo"),
        token_ttl_minutes=int(os.getenv("TOKEN_TTL_MINUTES", "480")),
    )
