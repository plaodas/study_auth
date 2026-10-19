from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.models.token import Token
from app.services import token_service


@pytest.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: Token.__table__.create(bind=sync_conn))
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_verify_and_consume_token_with_empty_raw_returns_none(session_factory):
    async with session_factory() as db:
        assert await token_service.verify_and_consume_token(db, raw=None, token_type="refresh") is None
        assert await token_service.verify_and_consume_token(db, raw="", token_type="refresh") is None


@pytest.mark.asyncio
async def test_create_and_verify_token_flow(session_factory):
    async with session_factory() as db:
        raw = await token_service.create_token(db, user_id=1, token_type="refresh", expires_delta=timedelta(minutes=10))
        assert isinstance(raw, str) and len(raw) > 0

        stored = (await db.execute(select(Token))).scalars().first()
        assert stored is not None
        assert stored.token_hash != raw
        assert len(stored.token_hash) == 64

        token = await token_service.verify_and_consume_token(db, raw, token_type="refresh")
        assert token is not None
        assert token.user_id == 1
        again = await token_service.verify_and_consume_token(db, raw, token_type="refresh")
        assert again is None


@pytest.mark.asyncio
async def test_expired_token_is_rejected(session_factory):
    async with session_factory() as db:
        raw = await token_service.create_token(db, user_id=1, token_type="refresh", expires_delta=timedelta(seconds=-5))
        assert await token_service.verify_and_consume_token(db, raw, token_type="refresh") is None
