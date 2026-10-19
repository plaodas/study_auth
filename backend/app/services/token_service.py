from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, or_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.token import Token

logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY must be set")


def _generate_raw_token(nbytes: int = 48) -> str:
    return secrets.token_urlsafe(nbytes)


def _hash_token(raw: str) -> str:
    return hmac.new(SECRET_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def _as_user_key(user_id: int | uuid.UUID | str) -> str:
    return str(user_id)


async def create_token(
    db: AsyncSession,
    user_id: int | uuid.UUID | str,
    token_type: str,
    expires_delta: Optional[timedelta] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    """Store an HMAC of a new random token and return the raw value once."""
    raw = _generate_raw_token()
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        if token_type == "refresh":
            days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7") or "7")
            expires_at = now + timedelta(days=days)
        else:
            expires_at = now + timedelta(hours=24)
    else:
        expires_at = now + expires_delta

    db.add(
        Token(
            user_id=_as_user_key(user_id),
            token_hash=_hash_token(raw),
            token_type=token_type,
            expires_at=expires_at,
            ip=ip,
            user_agent=user_agent,
        )
    )
    await db.commit()
    logger.info("created %s token for user_id=%s expires_at=%s", token_type, user_id, expires_at)
    return raw


async def verify_and_consume_token(db: AsyncSession, raw: str | None, token_type: str) -> Optional[Token]:
    """Atomically mark one unused, unexpired, unrevoked token as used."""
    if not raw:
        return None
    now = datetime.now(timezone.utc)
    stmt = (
        update(Token)
        .where(
            Token.token_hash == _hash_token(raw),
            Token.token_type == token_type,
            Token.revoked.is_(False),
            Token.used_at.is_(None),
            or_(Token.expires_at.is_(None), Token.expires_at > now),
        )
        .values(used_at=now)
        .returning(Token.id)
        # SQLite may load datetimes without tzinfo; skip identity-map evaluation.
        .execution_options(synchronize_session=False)
    )
    res = await db.execute(stmt)
    row = res.first()
    await db.commit()
    if not row:
        return None

    token = await db.get(Token, row[0])
    if token is None:
        return None
    # Unit tests store integer user ids. UUID strings are left as UUIDs.
    if isinstance(token.user_id, str) and token.user_id.isdigit():
        token.user_id = int(token.user_id)
    return token


async def revoke_token(db: AsyncSession, token_id: int) -> None:
    await db.execute(
        update(Token).where(Token.id == token_id).values(revoked=True).execution_options(synchronize_session=False)
    )
    await db.commit()


async def revoke_all_user_tokens(
    db: AsyncSession,
    user_id: int | uuid.UUID | str,
    token_type: Optional[str] = None,
) -> None:
    stmt = update(Token).where(Token.user_id == _as_user_key(user_id))
    if token_type:
        stmt = stmt.where(Token.token_type == token_type)
    await db.execute(stmt.values(revoked=True).execution_options(synchronize_session=False))
    await db.commit()


async def purge_expired_tokens(db: AsyncSession) -> int:
    """Delete rows whose expiry is already in the past."""
    now = datetime.now(timezone.utc)
    res = await db.execute(delete(Token).where(Token.expires_at.is_not(None), Token.expires_at < now))
    await db.commit()
    return int(res.rowcount or 0)
