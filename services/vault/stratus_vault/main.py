"""Stratus Vault — envelope-encrypted object storage.

This service is deliberately *untrusted*: it stores ciphertext plus the KMS-wrapped data key
and nothing else. It holds no KMS credentials, never calls the KMS, and only has the public
key needed to verify session tokens.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import jwt
from fastapi import Depends, FastAPI, File, Form, Header, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .db import Bucket, SessionLocal, StoredObject, VaultEvent, get_session, init_db, utcnow

settings = get_settings()
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
GCM_TAG_BYTES = 16
SEED_BUCKETS = [("acme-patient-records", "acme-health"), ("acme-billing-exports", "acme-health"),
                ("globex-ledgers", "globex-finance")]


class VaultError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


@dataclass(frozen=True)
class Principal:
    username: str
    tenant_id: str
    role: str


def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise VaultError("UnauthorizedException", "Sign in to continue", 401)
    try:
        claims = jwt.decode(authorization.split(" ", 1)[1], settings.jwt_public_key_pem, algorithms=["EdDSA"],
                            audience="stratus", issuer="stratus-kms")
    except jwt.PyJWTError as exc:
        raise VaultError("UnauthorizedException", "Your session is invalid or has expired", 401) from exc
    return Principal(claims["sub"], claims["tid"], claims["role"])


def log(session: Session, p: Principal | None, action: str, resource: str | None, outcome: str,
        detail: str = "") -> None:
    """Append an access-log event using the request's own DB connection (one connection per request)."""
    session.rollback()
    session.add(VaultEvent(tenant_id=p.tenant_id if p else None, actor=p.username if p else "anonymous",
                           action=action, resource=resource, outcome=outcome, detail=detail[:500]))
    session.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with SessionLocal() as s:
        if s.scalar(select(Bucket).limit(1)) is None:
            for name, tenant in SEED_BUCKETS:
                s.add(Bucket(name=name, tenant_id=tenant, created_by="stratus"))
            s.commit()
    yield


app = FastAPI(title="Stratus Vault", version="1.0.0", lifespan=lifespan,
              description="Untrusted object storage that only ever sees ciphertext and wrapped data keys.")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["X-Server-Time-Ms"])


@app.middleware("http")
async def timing_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Server-Time-Ms"] = f"{(time.perf_counter() - start) * 1000:.2f}"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(VaultError)
async def vault_error_handler(_: Request, exc: VaultError):
    return JSONResponse(status_code=exc.status, content={"error": exc.code, "message": exc.message})


def _iso(dt: datetime | None) -> str | None:
    """ISO-8601 with an explicit UTC offset. SQLite returns naive datetimes; we always store UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _bucket(session: Session, p: Principal, name: str, action: str) -> Bucket:
    bucket = session.scalar(select(Bucket).where(Bucket.name == name))
    if bucket is None:
        raise VaultError("NoSuchBucket", f"Bucket {name} does not exist", 404)
    if bucket.tenant_id != p.tenant_id:
        log(session, p, action, name, "AccessDenied", "cross-tenant request blocked")
        raise VaultError("AccessDenied", f"Bucket {name} belongs to another tenant", 403)
    return bucket


def _object(session: Session, bucket: Bucket, object_id: int) -> StoredObject:
    obj = session.get(StoredObject, object_id)
    if obj is None or obj.bucket_id != bucket.id:
        raise VaultError("NoSuchKey", "Object not found", 404)
    return obj


def object_view(o: StoredObject) -> dict:
    return {
        "id": o.id,
        "object_key": o.object_key,
        "content_type": o.content_type,
        "plaintext_size": o.plaintext_size,
        "stored_size": len(o.ciphertext),
        "ciphertext_sha256": o.ciphertext_sha256,
        "envelope": {
            "v": 1,
            "alg": "AES-256-GCM",
            "iv": o.iv,
            "ciphertext_blob": o.ciphertext_blob,
            "kms_key_id": o.kms_key_id,
            "kms_key_version": o.kms_key_version,
            "wrap_algorithm": o.wrap_algorithm,
            "encryption_context": json.loads(o.encryption_context),
        },
        "uploaded_by": o.uploaded_by,
        "created_at": _iso(o.created_at),
        "rewrapped_at": _iso(o.rewrapped_at),
    }


# ------------------------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"service": "stratus-vault", "status": "ok", "holds_kms_credentials": False}


class BucketIn(BaseModel):
    name: str = Field(min_length=3, max_length=63)
    default_key_id: str | None = None


@app.get("/buckets")
def list_buckets(p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    rows = session.execute(
        select(Bucket, func.count(StoredObject.id), func.coalesce(func.sum(StoredObject.plaintext_size), 0))
        .outerjoin(StoredObject).where(Bucket.tenant_id == p.tenant_id).group_by(Bucket.id).order_by(Bucket.name)
    ).all()
    return [{"name": b.name, "default_key_id": b.default_key_id, "created_at": _iso(b.created_at),
             "created_by": b.created_by, "object_count": n, "total_bytes": int(size)} for b, n, size in rows]


@app.post("/buckets", status_code=201)
def create_bucket(body: BucketIn, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    if not BUCKET_RE.match(body.name):
        raise VaultError("InvalidBucketName", "Use 3-63 lowercase letters, numbers and hyphens")
    session.add(Bucket(name=body.name, tenant_id=p.tenant_id, default_key_id=body.default_key_id, created_by=p.username))
    try:
        session.commit()
    except IntegrityError as exc:
        raise VaultError("BucketAlreadyExists", "That bucket name is already taken", 409) from exc
    log(session, p, "CreateBucket", body.name, "Success")
    return {"name": body.name}


@app.delete("/buckets/{name}", status_code=204)
def delete_bucket(name: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    bucket = _bucket(session, p, name, "DeleteBucket")
    if bucket.objects:
        raise VaultError("BucketNotEmpty", "Delete all objects first", 409)
    session.delete(bucket)
    session.commit()
    log(session, p, "DeleteBucket", name, "Success")
    return Response(status_code=204)


@app.get("/buckets/{name}/objects")
def list_objects(name: str, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    bucket = _bucket(session, p, name, "ListObjects")
    objs = session.scalars(select(StoredObject).where(StoredObject.bucket_id == bucket.id)
                           .order_by(StoredObject.created_at.desc())).all()
    return [object_view(o) for o in objs]


@app.post("/buckets/{name}/objects", status_code=201)
async def put_object(
    name: str,
    object_key: str = Form(..., min_length=1, max_length=255),
    envelope: str = Form(...),
    content_type: str = Form("application/octet-stream"),
    plaintext_size: int = Form(...),
    body: UploadFile = File(...),
    p: Principal = Depends(current_principal),
    session: Session = Depends(get_session),
):
    bucket = _bucket(session, p, name, "PutObject")
    ciphertext = await body.read(settings.max_object_bytes + GCM_TAG_BYTES + 1)
    if len(ciphertext) > settings.max_object_bytes + GCM_TAG_BYTES:
        raise VaultError("EntityTooLarge", f"Objects are limited to {settings.max_object_bytes // (1024 * 1024)} MB", 413)
    try:
        env = json.loads(envelope)
        iv = base64.b64decode(env["iv"], validate=True)
        base64.b64decode(env["ciphertext_blob"], validate=True)
        ctx = env["encryption_context"]
        assert env.get("alg") == "AES-256-GCM" and len(iv) == 12
    except (ValueError, KeyError, TypeError, AssertionError) as exc:
        raise VaultError("InvalidEnvelope", "Envelope metadata is missing or malformed") from exc
    expected = {"tenant": p.tenant_id, "bucket": name, "object": object_key}
    if ctx != expected:
        raise VaultError("InvalidEnvelope", "Encryption context must be exactly {tenant, bucket, object} for this upload")

    existing = session.scalar(select(StoredObject).where(StoredObject.bucket_id == bucket.id,
                                                         StoredObject.object_key == object_key))
    obj = existing or StoredObject(bucket_id=bucket.id, object_key=object_key)
    obj.content_type = content_type[:127]
    obj.plaintext_size = plaintext_size
    obj.ciphertext = ciphertext
    obj.ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    obj.iv = env["iv"]
    obj.ciphertext_blob = env["ciphertext_blob"]
    obj.kms_key_id = str(env["kms_key_id"])
    obj.kms_key_version = int(env["kms_key_version"])
    obj.wrap_algorithm = str(env.get("wrap_algorithm", "AES_KW"))
    obj.encryption_context = json.dumps(ctx, sort_keys=True)
    obj.uploaded_by = p.username
    obj.created_at = utcnow()
    obj.rewrapped_at = None
    session.add(obj)
    session.commit()
    log(session, p, "PutObject", f"{name}/{object_key}", "Success", f"{len(ciphertext)} ciphertext bytes")
    return object_view(obj)


@app.get("/buckets/{name}/objects/{object_id}")
def head_object(name: str, object_id: int, p: Principal = Depends(current_principal),
                session: Session = Depends(get_session)):
    return object_view(_object(session, _bucket(session, p, name, "GetObject"), object_id))


@app.get("/buckets/{name}/objects/{object_id}/body")
def get_object_body(name: str, object_id: int, p: Principal = Depends(current_principal),
                    session: Session = Depends(get_session)):
    obj = _object(session, _bucket(session, p, name, "GetObject"), object_id)
    log(session, p, "GetObject", f"{name}/{obj.object_key}", "Success")
    return Response(content=obj.ciphertext, media_type="application/octet-stream")


class RewrapIn(BaseModel):
    ciphertext_blob: str = Field(max_length=4096)
    kms_key_version: int


@app.patch("/buckets/{name}/objects/{object_id}/envelope")
def rewrap_object(name: str, object_id: int, body: RewrapIn, p: Principal = Depends(current_principal),
                  session: Session = Depends(get_session)):
    """Swap in a re-wrapped DEK after key rotation. The ciphertext payload is not touched."""
    obj = _object(session, _bucket(session, p, name, "RewrapObject"), object_id)
    obj.ciphertext_blob = body.ciphertext_blob
    obj.kms_key_version = body.kms_key_version
    obj.rewrapped_at = utcnow()
    session.commit()
    log(session, p, "RewrapObject", f"{name}/{obj.object_key}", "Success", f"now under key version {body.kms_key_version}")
    return object_view(obj)


@app.delete("/buckets/{name}/objects/{object_id}", status_code=204)
def delete_object(name: str, object_id: int, p: Principal = Depends(current_principal),
                  session: Session = Depends(get_session)):
    obj = _object(session, _bucket(session, p, name, "DeleteObject"), object_id)
    session.delete(obj)
    session.commit()
    log(session, p, "DeleteObject", f"{name}/{obj.object_key}", "Success")
    return Response(status_code=204)


@app.get("/audit")
def audit_log(limit: int = 100, p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    rows = session.scalars(select(VaultEvent).where(VaultEvent.tenant_id == p.tenant_id)
                           .order_by(VaultEvent.id.desc()).limit(min(limit, 500))).all()
    return [{"id": r.id, "at": _iso(r.at), "service": "vault", "actor": r.actor, "action": r.action,
             "resource": r.resource, "outcome": r.outcome, "detail": r.detail} for r in rows]


# ------------------------------------------------------------------------------------------
# Security Lab: simulate a fully compromised storage operator
# ------------------------------------------------------------------------------------------
def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


@app.get("/lab/storage-dump")
def storage_dump(p: Principal = Depends(current_principal), session: Session = Depends(get_session)):
    """Everything a malicious storage admin could read straight out of the database — across *all* tenants."""
    if not settings.demo_mode:
        raise VaultError("NotFound", "Not available", 404)
    log(session, p, "LabStorageDump", None, "Simulated", "attacker dumped the storage database")
    rows = session.scalars(select(StoredObject).order_by(StoredObject.id.desc()).limit(50)).all()
    return [{
        "tenant": o.bucket.tenant_id,
        "bucket": o.bucket.name,
        "object_key": o.object_key,
        "object_id": o.id,
        "stored_size": len(o.ciphertext),
        "ciphertext_hex_preview": o.ciphertext[:48].hex(),
        "entropy_bits_per_byte": round(_entropy(o.ciphertext[:4096]), 3),
        "iv": o.iv,
        "ciphertext_blob": o.ciphertext_blob,
        "encryption_context": json.loads(o.encryption_context),
        "kms_key_id": o.kms_key_id,
    } for o in rows]
