from __future__ import annotations

from sqlalchemy.orm import Session

from .db import AuditEvent, SessionLocal


def record(*, tenant_id: str | None, actor: str, action: str, outcome: str, key_id: str | None = None,
           detail: str = "", session: Session | None = None) -> None:
    """Append an audit event. Never contains key material, plaintext or ciphertext.

    When a request session is passed we reuse its connection (rolling back any half-done work
    first, so failed operations are still logged). This keeps one DB connection per request,
    which matters under heavy concurrency.
    """
    event = AuditEvent(tenant_id=tenant_id, actor=actor, action=action, key_id=key_id, outcome=outcome,
                       detail=detail[:500])
    if session is not None:
        session.rollback()
        session.add(event)
        session.commit()
        return
    with SessionLocal() as own:
        own.add(event)
        own.commit()
