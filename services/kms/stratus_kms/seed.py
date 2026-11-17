"""Demo tenants, users and keys. Runs once on an empty database."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import keys
from .auth import hash_password, principal_from_user
from .config import get_settings
from .db import Tenant, User

TENANTS = [("acme-health", "Acme Health"), ("globex-finance", "Globex Finance")]
USERS = [
    # username, display name, tenant, tenant role
    ("alice", "Alice", "acme-health", "admin"),
    ("bob", "Bob", "acme-health", "member"),
    ("mallory", "Mallory", "globex-finance", "admin"),
]


def seed(session: Session) -> bool:
    if session.scalar(select(Tenant).limit(1)) is not None:
        return False
    password = get_settings().demo_password
    for tid, name in TENANTS:
        session.add(Tenant(id=tid, name=name))
    for username, display, tid, role in USERS:
        session.add(User(username=username, display_name=display, tenant_id=tid, role=role,
                         password_hash=hash_password(password)))
    session.commit()

    def principal(username: str):
        return principal_from_user(session.scalar(select(User).where(User.username == username)))

    alice, mallory = principal("alice"), principal("mallory")
    records = keys.create_key(session, alice, "alias/patient-records", "Encrypts patient files in Acme buckets", "AES_KW")
    keys.set_access(session, alice, records.id, "bob", "user")
    rsa = keys.create_key(session, alice, "alias/billing-rsa", "RSA-2048-OAEP wrapping for billing exports", "RSA_2048_OAEP")
    keys.set_access(session, alice, rsa.id, "bob", "user")
    keys.create_key(session, mallory, "alias/ledger", "Globex general ledger", "AES_KW")
    return True
