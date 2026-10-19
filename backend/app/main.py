import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# Read .env before modules that refuse to start without secrets.
_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_ROOT / ".env")

from app.api import auth as auth_api  # noqa: E402
from app.api import jwks as jwks_api  # noqa: E402
from app.db.session import get_engine  # noqa: E402
from app.models import Base  # noqa: E402
from app.services.csrf import verify_csrf  # noqa: E402

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# Unsafe /api requests require a double-submit CSRF token except these routes.
_CSRF_EXEMPT = frozenset(
    {
        "/api/auth/signup",
        "/api/auth/token",
        "/api/auth/refresh",
        "/api/auth/confirm",
    }
)
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title="study-auth",
    description="JWT 認証の学習用 API。本番の認証基盤として使わないこと。",
    lifespan=lifespan,
)


@app.middleware("http")
async def csrf_protect(request: Request, call_next):
    if request.method in _UNSAFE_METHODS and request.url.path.startswith("/api"):
        if request.url.path not in _CSRF_EXEMPT:
            try:
                await verify_csrf(request)
            except HTTPException as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


app.include_router(auth_api.router, prefix="/api")
app.include_router(jwks_api.router)
