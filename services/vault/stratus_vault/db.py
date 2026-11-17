from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Bucket(Base):
    __tablename__ = "buckets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(63), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    default_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    objects: Mapped[list["StoredObject"]] = relationship(back_populates="bucket", cascade="all, delete-orphan")


class StoredObject(Base):
    """Everything the storage server ever learns about a file. Note: no plaintext, no usable key."""

    __tablename__ = "objects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bucket_id: Mapped[int] = mapped_column(ForeignKey("buckets.id"), index=True)
    object_key: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(127), default="application/octet-stream")
    plaintext_size: Mapped[int] = mapped_column(Integer)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64))
    iv: Mapped[str] = mapped_column(String(32))
    ciphertext_blob: Mapped[str] = mapped_column(Text)  # wrapped DEK from the KMS
    kms_key_id: Mapped[str] = mapped_column(String(36), index=True)
    kms_key_version: Mapped[int] = mapped_column(Integer)
    wrap_algorithm: Mapped[str] = mapped_column(String(32))
    encryption_context: Mapped[str] = mapped_column(Text)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rewrapped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    bucket: Mapped[Bucket] = relationship(back_populates="objects")

    __table_args__ = (UniqueConstraint("bucket_id", "object_key", name="uq_object_key"),)


class VaultEvent(Base):
    __tablename__ = "vault_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(48))
    resource: Mapped[str | None] = mapped_column(String(320), nullable=True)
    outcome: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text, default="")


def _normalise_url(url: str) -> str:
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


DATABASE_URL = _normalise_url(get_settings().database_url)
IS_SQLITE = DATABASE_URL.startswith("sqlite")
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False, "timeout": 30} if IS_SQLITE else {},
)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(conn, _):  # pragma: no cover
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
