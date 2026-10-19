from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import Index
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


@pytest.mark.asyncio
async def test_token_hash_unique_constraint():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    async with engine.begin() as conn:
        from app.models.token import Token

        await conn.run_sync(lambda sync_conn: Token.__table__.create(bind=sync_conn))
        await conn.run_sync(lambda sync_conn: Index("ux_tokens_token_hash", Token.token_hash, unique=True).create(sync_conn))

    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    async with Session() as session:
        from app.models.token import Token

        session.add(Token(user_id=1, token_hash="dup-hash", token_type="refresh", expires_at=expires))
        await session.commit()

        session.add(Token(user_id=2, token_hash="dup-hash", token_type="refresh", expires_at=expires))
        with pytest.raises(IntegrityError):
            await session.commit()

    await engine.dispose()
