"""Identity: tenants, users, password hashing and Ed25519-signed session tokens.

The KMS is the only service holding the token *signing* key. Stratus Vault receives
only the public key, so a compromised storage server cannot mint identities.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, Header
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import User, get_session, utcnow
from .errors import KMSError

ISSUER = "stratus-kms"
AUDIENCE = "stratus"

_settings = get_settings()
_private_key = serialization.load_pem_private_key(_settings.jwt_private_key_pem.encode(), password=None)
PUBLIC_KEY_PEM = _private_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(digest, base64.b64decode(digest_b64))


@dataclass(frozen=True)
class Principal:
    user_id: int
    username: str
    display_name: str
    tenant_id: str
    tenant_name: str
    role: str


def issue_token(user: User) -> str:
    now = utcnow()
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": user.username,
        "uid": user.id,
        "name": user.display_name,
        "tid": user.tenant_id,
        "tname": user.tenant.name,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=_settings.token_ttl_minutes)).timestamp()),
    }
    return jwt.encode(claims, _private_key, algorithm="EdDSA")


def principal_from_user(user: User) -> Principal:
    return Principal(user.id, user.username, user.display_name, user.tenant_id, user.tenant.name, user.role)


def current_principal(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise KMSError("UnauthorizedException", "Sign in to continue", 401)
    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, _private_key.public_key(), algorithms=["EdDSA"], audience=AUDIENCE, issuer=ISSUER)
    except jwt.PyJWTError as exc:
        raise KMSError("UnauthorizedException", "Your session is invalid or has expired", 401) from exc
    user = session.scalar(select(User).where(User.username == claims["sub"]))
    if user is None:
        raise KMSError("UnauthorizedException", "Unknown user", 401)
    return principal_from_user(user)
