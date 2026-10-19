"""Test process secrets. Generated in memory and never written to the repo."""

import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
import pytest

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
os.environ["JWT_PRIVATE_KEY"] = _key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
os.environ["JWT_PUBLIC_KEY"] = _key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
os.environ.pop("JWT_PRIVATE_KEY_PATH", None)
os.environ.pop("JWT_PUBLIC_KEY_PATH", None)
os.environ["JWT_USE_KEYS_DIR"] = "0"
os.environ.pop("JWT_PUBLIC_KEYS_DIR", None)
os.environ["SECRET_KEY"] = secrets.token_urlsafe(32)
os.environ["CSRF_SECRET"] = secrets.token_urlsafe(32)
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["COOKIE_SECURE"] = "0"
os.environ.pop("SMTP_HOST", None)


@pytest.fixture
async def client():
    from app.db.session import get_engine
    from app.main import app
    from app.models import Base

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver", trust_env=False) as ac:
        yield ac
