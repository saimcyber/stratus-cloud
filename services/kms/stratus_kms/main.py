"""Stratus KMS — REST API.

Trust boundary: this service only ever handles 32-byte data keys and their wrapped form.
User files are encrypted in the browser and stored by Stratus Vault; they never reach the KMS.
"""
from __future__ import annotations

import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, keys, ratelimit
from .auth import PUBLIC_KEY_PEM, Principal, current_principal, issue_token, principal_from_user, verify_password
from .config import get_settings
from .db import CMK, AuditEvent, SessionLocal, User, get_session, init_db
from .errors import KMSError
from .seed import seed

settings = get_settings()


def _sweeper(stop: threading.Event) -> None:
    while not stop.wait(10):
        try:
            with SessionLocal() as s:
                for _ in range(keys.process_due_deletions(s)):
                    audit.record(tenant_id=None, actor="stratus-kms", action="DeleteKeyMaterial", outcome="Success",
                                 detail="Pending-deletion window elapsed; key material destroyed")
        except Exception:  # pragma: no cover - keep the sweeper alive
            pass


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with SessionLocal() as s:
        seed(s)
    stop = threading.Event()
    threading.Thread(target=_sweeper, args=(stop,), daemon=True).start()
    yield
    stop.set()


app = FastAPI(title="Stratus KMS", version="1.0.0", lifespan=lifespan,
              description="Key management service: Root KEK → CMK → DEK envelope encryption.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Server-Time-Ms"],
)


@app.middleware("http")
async def timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Server-Time-Ms"] = f"{(time.perf_counter() - start) * 1000:.2f}"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(KMSError)
async def kms_error_handler(_: Request, exc: KMSError):
    return JSONResponse(status_code=exc.status, content={"error": exc.code, "message": exc.message})


# ------------------------------------------------------------------------------------------
# Schemas
# ------------------------------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str
    password: str


class DemoLoginIn(BaseModel):
    username: str


class CreateKeyIn(BaseModel):
    alias: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    algorithm: str = "AES_KW"


class DeletionIn(BaseModel):
    pending_minutes: int = Field(default=7 * 24 * 60)


class AccessIn(BaseModel):
    username: str
    role: str | None


class DataKeyIn(BaseModel):
    encryption_context: dict[str, str]


class BlobIn(BaseModel):
    ciphertext_blob: str = Field(max_length=4096)
    encryption_context: dict[str, str]


def _iso(dt: datetime | None) -> str | None:
    """ISO-8601 with an explicit UTC offset. SQLite returns naive datetimes; we always store UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def key_view(cmk: CMK, p: Principal) -> dict:
    return {
        "key_id": cmk.id,
        "alias": cmk.alias,
        "description": cmk.description,
        "algorithm": cmk.algorithm,
        "state": cmk.state,
        "primary_version": cmk.primary_version,
        "created_by": cmk.created_by,
        "created_at": _iso(cmk.created_at),
        "deletion_date": _iso(cmk.deletion_date),
        "root_key_id": cmk.root_key_id,
        "my_role": keys.key_role(cmk, p),
        "versions": [
            {
                "version": v.version,
                "created_at": _iso(v.created_at),
                "status": "Destroyed" if v.destroyed else ("Primary" if v.version == cmk.primary_version else "Decrypt only"),
                "public_key_pem": v.public_key_pem,
            }
            for v in cmk.versions
        ],
        "access": [{"username": a.user.username, "display_name": a.user.display_name, "role": a.role} for a in cmk.access],
    }


def run(session: Session, action: str, p: Principal, key_id: str | None, fn, *, detail: str = ""):
    """Execute an operation and write an audit event for success *and* failure."""
    try:
        result = fn()
    except KMSError as exc:
        audit.record(tenant_id=p.tenant_id, actor=p.username, action=action, key_id=key_id, outcome=exc.code,
                     detail=exc.message, session=session)
        raise
    audit.record(tenant_id=p.tenant_id, actor=p.username, action=action, key_id=key_id, outcome="Success",
                 detail=detail, session=session)
    return result


# ------------------------------------------------------------------------------------------
# Health + identity
# ------------------------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"service": "stratus-kms", "status": "ok", "root_key_id": keys.ROOT.key_id, "demo_mode": settings.demo_mode}


@app.get("/auth/public-key")
def public_key():
    """Token verification key. Stratus Vault pins this value through its own env config."""
    return {"algorithm": "EdDSA", "public_key_pem": PUBLIC_KEY_PEM}


def _login_response(user: User) -> dict:
    p = principal_from_user(user)
    return {"token": issue_token(user), "user": p.__dict__}


@app.post("/auth/login")
def login(body: LoginIn, session: Session = Depends(get_session)):
    wait = ratelimit.login_failures.locked_for(body.username)
    if wait > 0:
        raise KMSError("ThrottlingException", f"Too many failed sign-in attempts. Try again in {int(wait) + 1}s.", 429)
    user = session.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        ratelimit.login_failures.record_failure(body.username)
        audit.record(tenant_id=user.tenant_id if user else None, actor=body.username, action="SignIn",
                     outcome="InvalidCredentials", session=session)
        raise KMSError("UnauthorizedException", "Incorrect username or password", 401)
    ratelimit.login_failures.reset(body.username)
    audit.record(tenant_id=user.tenant_id, actor=user.username, action="SignIn", outcome="Success", session=session)
    return _login_response(user)


@app.get("/auth/personas")
def personas(session: Session = Depends(get_session)):
    if not settings.demo_mode:
        return []
    users = session.scalars(select(User).order_by(User.id)).all()
    return [{"username": u.username, "display_name": u.display_name, "tenant_id": u.tenant_id,
             "tenant_name": u.tenant.name, "role": u.role} for u in users]


@app.post("/auth/demo-login")
def demo_login(body: DemoLoginIn, session: Session = Depends(get_session)):
    if not settings.demo_mode:
        raise KMSError("UnauthorizedException", "Demo sign-in is disabled", 401)
    user = session.scalar(select(User).where(User.username == body.username))
    if user is None:
        raise KMSError("UnauthorizedException", "Unknown persona", 401)
    audit.record(tenant_id=user.tenant_id, actor=user.username, action="SignIn", outcome="Success", detail="demo persona",
                 session=session)
    return _login_response(user)


@app.get("/auth/me")
def me(p: Principal = Depends(current_principal)):
    return p.__dict__


@app.get("/tenant/users")
def tenant_users(p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    users = session.scalars(select(User).where(User.tenant_id == p.tenant_id).order_by(User.id)).all()
    return [{"username": u.username, "display_name": u.display_name, "role": u.role} for u in users]


# ------------------------------------------------------------------------------------------
# Keys
# ------------------------------------------------------------------------------------------
@app.get("/keys")
def list_keys(p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    keys.process_due_deletions(session)
    return [key_view(k, p) for k in keys.list_keys(session, p)]


@app.post("/keys", status_code=201)
def create_key(body: CreateKeyIn, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    cmk = run(session, "CreateKey", p, None, lambda: keys.create_key(session, p, body.alias, body.description, body.algorithm),
              detail=f"{body.alias} ({body.algorithm})")
    return key_view(cmk, p)


@app.get("/keys/{key_id}")
def describe_key(key_id: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    keys.process_due_deletions(session)
    return key_view(keys.authorize(session, p, key_id, "view"), p)


@app.post("/keys/{key_id}/rotate")
def rotate_key(key_id: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    cmk, minted = run(session, "RotateKeyOnDemand", p, key_id, lambda: keys.rotate(session, p, key_id))
    return {**key_view(cmk, p), "rotated_to_version": minted}


@app.post("/keys/{key_id}/disable")
def disable_key(key_id: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    run(session, "DisableKey", p, key_id, lambda: keys.set_enabled(session, p, key_id, False))
    return key_view(keys.authorize(session, p, key_id, "view"), p)


@app.post("/keys/{key_id}/enable")
def enable_key(key_id: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    run(session, "EnableKey", p, key_id, lambda: keys.set_enabled(session, p, key_id, True))
    return key_view(keys.authorize(session, p, key_id, "view"), p)


@app.post("/keys/{key_id}/schedule-deletion")
def schedule_deletion(key_id: str, body: DeletionIn, p: Principal = Depends(current_principal),
                      session: Session = Depends(get_session)):
    cmk = run(session, "ScheduleKeyDeletion", p, key_id, lambda: keys.schedule_deletion(session, p, key_id, body.pending_minutes),
              detail=f"pending window {body.pending_minutes} min")
    return key_view(cmk, p)


@app.post("/keys/{key_id}/cancel-deletion")
def cancel_deletion(key_id: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    run(session, "CancelKeyDeletion", p, key_id, lambda: keys.cancel_deletion(session, p, key_id))
    return key_view(keys.authorize(session, p, key_id, "view"), p)


@app.put("/keys/{key_id}/access")
def set_access(key_id: str, body: AccessIn, p: Principal = Depends(current_principal),
               session: Session = Depends(get_session)):
    cmk = run(session, "PutKeyAccess", p, key_id, lambda: keys.set_access(session, p, key_id, body.username, body.role),
              detail=f"{body.username} -> {body.role or 'removed'}")
    return key_view(cmk, p)


# ------------------------------------------------------------------------------------------
# Data keys
# ------------------------------------------------------------------------------------------
@app.post("/keys/{key_id}/generate-data-key")
def generate_data_key(key_id: str, body: DataKeyIn, p: Principal = Depends(current_principal),
                      session: Session = Depends(get_session)):
    return run(session, "GenerateDataKey", p, key_id, lambda: keys.generate_data_key(session, p, key_id, body.encryption_context),
               detail=_ctx_detail(body.encryption_context))


@app.post("/decrypt")
def decrypt(body: BlobIn, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    return run(session, "Decrypt", p, _blob_key_id(body.ciphertext_blob),
               lambda: keys.decrypt(session, p, body.ciphertext_blob, body.encryption_context),
               detail=_ctx_detail(body.encryption_context))


@app.post("/re-encrypt")
def re_encrypt(body: BlobIn, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    return run(session, "ReEncrypt", p, _blob_key_id(body.ciphertext_blob),
               lambda: keys.re_encrypt(session, p, body.ciphertext_blob, body.encryption_context),
               detail=_ctx_detail(body.encryption_context))


def _ctx_detail(ctx: dict[str, str]) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(ctx.items()))


def _blob_key_id(blob_b64: str) -> str | None:
    try:
        return keys._parse(blob_b64).cmk_id
    except KMSError:
        return None


# ------------------------------------------------------------------------------------------
# Audit
# ------------------------------------------------------------------------------------------
@app.get("/audit")
def audit_log(limit: int = 100, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    rows = session.scalars(
        select(AuditEvent).where(AuditEvent.tenant_id == p.tenant_id).order_by(AuditEvent.id.desc()).limit(min(limit, 500))
    ).all()
    return [{"id": r.id, "at": _iso(r.at), "service": "kms", "actor": r.actor, "action": r.action, "key_id": r.key_id,
             "outcome": r.outcome, "detail": r.detail} for r in rows]
