import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from app.services.csrf import make_csrf_token, verify_csrf, verify_csrf_token


def _app():
    app = FastAPI()

    @app.post("/protected")
    async def protected(dep=Depends(verify_csrf)):
        return {"status": "ok"}

    return app


async def _post(app, headers=None, cookies=None):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        for name, value in (cookies or {}).items():
            ac.cookies.set(name, value)
        return await ac.post("/protected", headers=headers)


def test_csrf_token_verifies_when_signature_contains_a_dot():
    import base64

    saw_dot = False
    for index in range(200):
        token = make_csrf_token(f"session-{index}")
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        if b"." in raw[-32:]:
            saw_dot = True
        session_id, ok, expired = verify_csrf_token(token)
        assert session_id == f"session-{index}"
        assert ok is True
        assert expired is False
    assert saw_dot


@pytest.mark.asyncio
async def test_csrf_double_submit_happy_path():
    csrf = make_csrf_token("session-1")
    response = await _post(_app(), headers={"x-csrf-token": csrf}, cookies={"csrf_token": csrf})
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_csrf_double_submit_missing_header_fails():
    csrf = make_csrf_token("session-1")
    response = await _post(_app(), cookies={"csrf_token": csrf})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_csrf_double_submit_mismatch_fails():
    csrf = make_csrf_token("session-1")
    response = await _post(_app(), headers={"x-csrf-token": csrf}, cookies={"csrf_token": "other"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_csrf_double_submit_expired_returns_419():
    csrf = make_csrf_token("session-1", expires=-60)
    response = await _post(_app(), headers={"x-csrf-token": csrf}, cookies={"csrf_token": csrf})
    assert response.status_code == 419
