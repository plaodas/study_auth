import asyncio
from datetime import timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models.token import Token
from app.services import token_service


@pytest.fixture
async def session_factory(tmp_path):
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path}/tokens.db",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: Token.__table__.create(bind=sync_conn))
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_refresh_consumption(session_factory):
    async with session_factory() as db:
        raw = await token_service.create_token(db, user_id=1, token_type="refresh", expires_delta=timedelta(minutes=10))

    async def attempt_consume():
        async with session_factory() as db:
            return await token_service.verify_and_consume_token(db, raw, token_type="refresh")

    results = await asyncio.gather(attempt_consume(), attempt_consume())
    assert len([row for row in results if row is not None]) == 1
    assert len([row for row in results if row is None]) == 1
