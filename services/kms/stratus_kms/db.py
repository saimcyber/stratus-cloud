from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_url(url: str) -> str:
    # Neon / Render hand out postgres:// or postgresql:// URLs; we use the psycopg3 driver.
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # tenant role: admin | member
    password_hash: Mapped[str] = mapped_column(String(255))
    tenant: Mapped[Tenant] = relationship()


class CMK(Base):
    __tablename__ = "cmks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    alias: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    algorithm: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(24), default="Enabled")
    primary_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    deletion_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    root_key_id: Mapped[str] = mapped_column(String(32))
    versions: Mapped[list["CMKVersion"]] = relationship(back_populates="cmk", order_by="CMKVersion.version")
    access: Mapped[list["KeyAccess"]] = relationship(back_populates="cmk", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("tenant_id", "alias", name="uq_alias_per_tenant"),)


class CMKVersion(Base):
    __tablename__ = "cmk_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cmk_id: Mapped[str] = mapped_column(ForeignKey("cmks.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    wrapped_material: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    wrapped_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    destroyed: Mapped[bool] = mapped_column(Boolean, default=False)
    cmk: Mapped[CMK] = relationship(back_populates="versions")

    __table_args__ = (UniqueConstraint("cmk_id", "version", name="uq_cmk_version"),)


class KeyAccess(Base):
    __tablename__ = "key_access"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cmk_id: Mapped[str] = mapped_column(ForeignKey("cmks.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(String(16))  # admin | user
    cmk: Mapped[CMK] = relationship(back_populates="access")
    user: Mapped[User] = relationship()

    __table_args__ = (UniqueConstraint("cmk_id", "user_id", name="uq_key_user"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(48))
    key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    outcome: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text, default="")


settings = get_settings()
DATABASE_URL = _normalise_url(settings.database_url)
IS_SQLITE = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False, "timeout": 30} if IS_SQLITE else {},
    pool_size=10,
    max_overflow=30,
)

if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(conn, _):  # pragma: no cover - driver hook
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
