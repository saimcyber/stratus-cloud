"""Key lifecycle + data-key operations. All functions are tenant-scoped and ACL-checked."""
from __future__ import annotations

import base64
import threading
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from . import crypto, ratelimit
from .auth import Principal
from .config import get_settings
from .db import CMK, CMKVersion, KeyAccess, User, utcnow
from .errors import KMSError, access_denied, disabled, invalid_ciphertext, invalid_state, not_found, throttled
from .zeroize import zeroize

_settings = get_settings()
ROOT = crypto.RootKeyring(_settings.root_kek_b64)

# Per-key in-process locks complement the database row lock (SELECT ... FOR UPDATE on Postgres)
# so that two concurrent rotations can never mint the same version number.
_rotation_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _rotation_lock(key_id: str) -> threading.Lock:
    with _locks_guard:
        return _rotation_locks.setdefault(key_id, threading.Lock())


# ------------------------------------------------------------------------------------------
# Lookup + authorisation
# ------------------------------------------------------------------------------------------
def _load(session: Session, key_id: str, *, for_update: bool = False) -> CMK:
    try:
        uuid.UUID(key_id)
    except ValueError as exc:
        raise not_found() from exc
    stmt = select(CMK).where(CMK.id == key_id).options(selectinload(CMK.versions), selectinload(CMK.access))
    if for_update:
        stmt = stmt.with_for_update()
    cmk = session.scalar(stmt)
    if cmk is None:
        raise not_found()
    return cmk


def key_role(cmk: CMK, p: Principal) -> str | None:
    for entry in cmk.access:
        if entry.user_id == p.user_id:
            return entry.role
    return None


def authorize(session: Session, p: Principal, key_id: str, need: str, *, for_update: bool = False) -> CMK:
    """need = 'view' | 'use' | 'manage'. Cross-tenant access is always denied."""
    if ratelimit.denied_calls.locked_for(p.username) > 0:
        raise throttled("Too many denied requests. Try again in a few seconds.")
    cmk = _load(session, key_id, for_update=for_update)
    if cmk.tenant_id != p.tenant_id:
        ratelimit.denied_calls.record_failure(p.username)
        raise access_denied(f"User {p.username} ({p.tenant_id}) cannot access a key owned by another tenant")
    role = key_role(cmk, p)
    allowed = {
        "view": True,
        "use": role in ("user", "admin"),
        "manage": role == "admin",
    }[need]
    if not allowed:
        ratelimit.denied_calls.record_failure(p.username)
        raise access_denied(f"User {p.username} is not on the access list of this key for '{need}'")
    return cmk


def _require_usable(cmk: CMK) -> None:
    if cmk.state == "Disabled":
        raise disabled(f"Key {cmk.alias} is disabled")
    if cmk.state == "PendingDeletion":
        raise invalid_state(f"Key {cmk.alias} is pending deletion and cannot be used")
    if cmk.state == "Deleted":
        raise invalid_state(f"Key {cmk.alias} has been deleted; data encrypted under it is unrecoverable")


def _check_context(p: Principal, ctx: dict[str, str]) -> None:
    if ctx.get("tenant") != p.tenant_id:
        ratelimit.denied_calls.record_failure(p.username)
        raise access_denied("Encryption context must name your own tenant")


def _throttle(p: Principal) -> None:
    if not ratelimit.crypto_calls.allow(p.username):
        raise throttled()


# ------------------------------------------------------------------------------------------
# Lifecycle
# ------------------------------------------------------------------------------------------
def process_due_deletions(session: Session) -> int:
    """Crypto-shred keys whose pending-deletion window has elapsed."""
    due = session.scalars(
        select(CMK).where(CMK.state == "PendingDeletion", CMK.deletion_date <= utcnow()).options(selectinload(CMK.versions))
    ).all()
    for cmk in due:
        for v in cmk.versions:
            v.wrapped_material = None
            v.wrapped_private_key = None
            v.destroyed = True
        cmk.state = "Deleted"
    if due:
        session.commit()
    return len(due)


def list_keys(session: Session, p: Principal) -> list[CMK]:
    return list(
        session.scalars(
            select(CMK).where(CMK.tenant_id == p.tenant_id).options(selectinload(CMK.versions), selectinload(CMK.access))
            .order_by(CMK.created_at)
        ).all()
    )


def create_key(session: Session, p: Principal, alias: str, description: str, algorithm: str) -> CMK:
    if algorithm not in crypto.ALGORITHMS:
        raise KMSError("ValidationException", f"algorithm must be one of {', '.join(crypto.ALGORITHMS)}")
    alias = alias.strip()
    if not alias.startswith("alias/"):
        alias = "alias/" + alias
    if len(alias) < 7 or len(alias) > 120:
        raise KMSError("ValidationException", "Alias must be 1-113 characters after 'alias/'")
    if session.scalar(select(CMK).where(CMK.tenant_id == p.tenant_id, CMK.alias == alias)):
        raise KMSError("AlreadyExistsException", f"{alias} already exists in your account", 409)

    new = crypto.create_cmk_version(ROOT, algorithm)
    cmk = CMK(id=str(uuid.uuid4()), tenant_id=p.tenant_id, alias=alias, description=description.strip(),
              algorithm=algorithm, state="Enabled", primary_version=1, created_by=p.username, root_key_id=ROOT.key_id)
    cmk.versions.append(CMKVersion(version=1, wrapped_material=new.wrapped_material,
                                   wrapped_private_key=new.wrapped_private_key, public_key_pem=new.public_key_pem))
    cmk.access.append(KeyAccess(user_id=p.user_id, role="admin"))
    session.add(cmk)
    session.commit()
    return _load(session, cmk.id)


def rotate(session: Session, p: Principal, key_id: str) -> tuple[CMK, int]:
    """Mint a new primary version. Returns the CMK and the version number this call created."""
    with _rotation_lock(key_id):
        for attempt in range(3):
            cmk = authorize(session, p, key_id, "manage", for_update=True)
            _require_usable(cmk)
            next_version = max(v.version for v in cmk.versions) + 1
            new = crypto.create_cmk_version(ROOT, cmk.algorithm)
            session.add(CMKVersion(cmk_id=cmk.id, version=next_version, wrapped_material=new.wrapped_material,
                                   wrapped_private_key=new.wrapped_private_key, public_key_pem=new.public_key_pem))
            cmk.primary_version = next_version
            try:
                session.commit()
                break
            except IntegrityError:  # another worker won the race; retry with a fresh read
                session.rollback()
                if attempt == 2:
                    raise
    session.expire_all()
    return _load(session, key_id), next_version


def set_enabled(session: Session, p: Principal, key_id: str, enabled: bool) -> CMK:
    cmk = authorize(session, p, key_id, "manage", for_update=True)
    if cmk.state in ("PendingDeletion", "Deleted"):
        raise invalid_state(f"Cannot change a key in state {cmk.state}")
    cmk.state = "Enabled" if enabled else "Disabled"
    session.commit()
    return cmk


def schedule_deletion(session: Session, p: Principal, key_id: str, pending_minutes: int) -> CMK:
    if _settings.demo_mode:
        if not 0 <= pending_minutes <= 60 * 24 * 30:
            raise KMSError("ValidationException", "Pending window must be between 0 minutes and 30 days")
    elif not 7 * 24 * 60 <= pending_minutes <= 30 * 24 * 60:
        raise KMSError("ValidationException", "Pending window must be between 7 and 30 days")
    cmk = authorize(session, p, key_id, "manage", for_update=True)
    if cmk.state == "Deleted":
        raise invalid_state("Key is already deleted")
    cmk.state = "PendingDeletion"
    cmk.deletion_date = utcnow() + timedelta(minutes=pending_minutes)
    session.commit()
    process_due_deletions(session)
    return _load(session, key_id)


def cancel_deletion(session: Session, p: Principal, key_id: str) -> CMK:
    cmk = authorize(session, p, key_id, "manage", for_update=True)
    if cmk.state != "PendingDeletion":
        raise invalid_state("Key is not pending deletion")
    cmk.state = "Disabled"  # same as AWS: a cancelled key comes back disabled
    cmk.deletion_date = None
    session.commit()
    return cmk


def set_access(session: Session, p: Principal, key_id: str, username: str, role: str | None) -> CMK:
    cmk = authorize(session, p, key_id, "manage")
    user = session.scalar(select(User).where(User.username == username))
    if user is None or user.tenant_id != p.tenant_id:
        raise KMSError("ValidationException", "Users can only be granted access to keys in their own tenant")
    if role not in (None, "user", "admin"):
        raise KMSError("ValidationException", "role must be 'user', 'admin' or null")
    if user.id == p.user_id and role != "admin":
        raise KMSError("ValidationException", "You cannot remove your own admin access")
    existing = next((a for a in cmk.access if a.user_id == user.id), None)
    if role is None and existing is not None:
        session.delete(existing)
    elif role is not None and existing is not None:
        existing.role = role
    elif role is not None:
        session.add(KeyAccess(cmk_id=cmk.id, user_id=user.id, role=role))
    session.commit()
    session.expire_all()
    return _load(session, key_id)


# ------------------------------------------------------------------------------------------
# Data-key operations (the KMS never sees the payload — only 32-byte DEKs)
# ------------------------------------------------------------------------------------------
def _unseal(cmk: CMK, version_no: int) -> crypto.UnsealedVersion:
    version = next((v for v in cmk.versions if v.version == version_no), None)
    if version is None or version.destroyed or version.wrapped_material is None:
        raise invalid_ciphertext("The key version that protected this data no longer exists")
    try:
        return crypto.unseal_version(ROOT, cmk.algorithm, version.wrapped_material, version.wrapped_private_key,
                                     version.public_key_pem)
    except crypto.CryptoError as exc:
        raise KMSError("KMSInternalException", "Key material integrity check failed", 500) from exc


def generate_data_key(session: Session, p: Principal, key_id: str, ctx: dict[str, str]) -> dict:
    _throttle(p)
    cmk = authorize(session, p, key_id, "use")
    _require_usable(cmk)
    _check_context(p, ctx)
    version_no = cmk.primary_version
    unsealed = _unseal(cmk, version_no)
    dek = crypto.random_key()
    try:
        blob = crypto.wrap_dek(unsealed, cmk.id, version_no, dek, ctx)
        plaintext_b64 = base64.b64encode(bytes(dek)).decode()
    finally:
        zeroize(dek)
        unsealed.wipe()
    return {
        "key_id": cmk.id,
        "key_alias": cmk.alias,
        "key_version": version_no,
        "algorithm": cmk.algorithm,
        "plaintext": plaintext_b64,
        "ciphertext_blob": base64.b64encode(blob).decode(),
    }


def _parse(blob_b64: str) -> crypto.ParsedBlob:
    try:
        return crypto.parse_blob(base64.b64decode(blob_b64, validate=True))
    except (ValueError, crypto.CryptoError) as exc:
        raise invalid_ciphertext("The ciphertext blob is malformed") from exc


def decrypt(session: Session, p: Principal, blob_b64: str, ctx: dict[str, str]) -> dict:
    _throttle(p)
    parsed = _parse(blob_b64)
    cmk = authorize(session, p, parsed.cmk_id, "use")
    _require_usable(cmk)
    _check_context(p, ctx)
    unsealed = _unseal(cmk, parsed.version)
    try:
        dek = crypto.unwrap_dek(unsealed, parsed, ctx)
    except crypto.CryptoError as exc:
        ratelimit.denied_calls.record_failure(p.username)
        raise invalid_ciphertext(str(exc)) from exc
    finally:
        unsealed.wipe()
    try:
        plaintext_b64 = base64.b64encode(bytes(dek)).decode()
    finally:
        zeroize(dek)
    return {"key_id": cmk.id, "key_alias": cmk.alias, "key_version": parsed.version, "plaintext": plaintext_b64}


def re_encrypt(session: Session, p: Principal, blob_b64: str, ctx: dict[str, str]) -> dict:
    """Unwrap under the old version and re-wrap under the primary version — the DEK never leaves the KMS."""
    _throttle(p)
    parsed = _parse(blob_b64)
    cmk = authorize(session, p, parsed.cmk_id, "use")
    _require_usable(cmk)
    _check_context(p, ctx)
    old = _unseal(cmk, parsed.version)
    try:
        dek = crypto.unwrap_dek(old, parsed, ctx)
    except crypto.CryptoError as exc:
        raise invalid_ciphertext(str(exc)) from exc
    finally:
        old.wipe()
    new = _unseal(cmk, cmk.primary_version)
    try:
        blob = crypto.wrap_dek(new, cmk.id, cmk.primary_version, dek, ctx)
    finally:
        zeroize(dek)
        new.wipe()
    return {
        "key_id": cmk.id,
        "source_version": parsed.version,
        "key_version": cmk.primary_version,
        "ciphertext_blob": base64.b64encode(blob).decode(),
    }
