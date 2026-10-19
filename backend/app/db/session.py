from __future__ import annotations

import os
from typing import AsyncGenerator, Optional

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

_engine: Optional[AsyncEngine] = None
_SessionLocal: Optional[async_sessionmaker[AsyncSession]] = None


def database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./study_auth.db")


def get_engine() -> AsyncEngine:
    global _engine, _SessionLocal
    if _engine is None:
        url = database_url()
        kwargs: dict = {}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            # One shared connection so ``:memory:`` survives across requests.
            if ":memory:" in url or "mode=memory" in url:
                kwargs["poolclass"] = StaticPool
        else:
            kwargs["pool_pre_ping"] = True
        _engine = create_async_engine(url, **kwargs)
        _SessionLocal = async_sessionmaker(bind=_engine, class_=AsyncSession, expire_on_commit=False)
        if url.startswith("sqlite"):

            @event.listens_for(_engine.sync_engine, "connect")
            def _enable_sqlite_fk(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

    return _engine


def SessionLocal() -> AsyncSession:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session
