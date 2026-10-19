import base64
import re
import time
from http.cookies import SimpleCookie

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from httpx import ASGITransport, AsyncClient
from jose import jwt

from app.main import app
from app.services.csrf import make_csrf_token


@app.post("/api/csrf-probe")
async def csrf_probe():
    return {"ok": True}


def _confirm_token(caplog: pytest.LogCaptureFixture) -> str:
    found = []
    for record in caplog.records:
        found.extend(re.findall(r"token=([A-Za-z0-9_\-]+)", record.getMessage()))
    assert found, "confirmation url was not logged"
    return found[-1]


def _set_cookie(response, name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        if name in parsed:
            return header
    raise AssertionError(f"missing set-cookie {name}")


def _cookie_value(response, name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        if name in parsed:
            return parsed[name].value
    raise AssertionError(f"missing set-cookie {name}")


async def _signup(client, caplog, email="learner@example.com", password="password123", name="Learner"):
    caplog.set_level("INFO")
    response = await client.post(
        "/api/auth/signup",
        json={"email": email, "password": password, "name": name},
    )
    assert response.status_code == 201
    body = response.json()
    assert set(body) == {"id", "email"}
    assert body["email"] == email
    return body


@pytest.mark.asyncio
async def test_unverified_user_cannot_login_until_confirm(client, caplog):
    await _signup(client, caplog)
    denied = await client.post(
        "/api/auth/token",
        data={"username": "learner@example.com", "password": "password123"},
    )
    assert denied.status_code == 403

    token = _confirm_token(caplog)
    confirmed = await client.get("/api/auth/confirm", params={"token": token})
    assert confirmed.status_code == 200
    again = await client.get("/api/auth/confirm", params={"token": token})
    assert again.status_code == 400

    logged_in = await client.post(
        "/api/auth/token",
        data={"username": "learner@example.com", "password": "password123"},
    )
    assert logged_in.status_code == 200
    assert logged_in.json() == {"token_type": "bearer"}
    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "learner@example.com"
    assert me.json()["mail_verified"] is True


@pytest.mark.asyncio
async def test_refresh_rotates_and_logout_revokes(client, caplog):
    await _signup(client, caplog, email="rotate@example.com")
    await client.get("/api/auth/confirm", params={"token": _confirm_token(caplog)})
    logged_in = await client.post(
        "/api/auth/token",
        data={"username": "rotate@example.com", "password": "password123"},
    )
    assert logged_in.status_code == 200
    old_refresh = _cookie_value(logged_in, "refresh_token")
    access_cookie = _set_cookie(logged_in, "access_token").lower()
    refresh_cookie = _set_cookie(logged_in, "refresh_token").lower()
    csrf_cookie = _set_cookie(logged_in, "csrf_token").lower()
    assert "httponly" in access_cookie
    assert "httponly" in refresh_cookie
    assert "httponly" not in csrf_cookie
    assert "samesite=lax" in access_cookie
    assert "secure" not in access_cookie.split(";", 1)[1]

    refreshed = await client.post("/api/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json() == {"token_type": "bearer"}
    new_refresh = _cookie_value(refreshed, "refresh_token")
    assert new_refresh != old_refresh

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver", trust_env=False) as other:
        other.cookies.set("refresh_token", old_refresh)
        stale = await other.post("/api/auth/refresh")
        assert stale.status_code == 401
        other.cookies.clear()
        other.cookies.set("refresh_token", new_refresh)
        current = await other.post("/api/auth/refresh")
        assert current.status_code == 200
        latest = _cookie_value(current, "refresh_token")
        csrf = _cookie_value(current, "csrf_token")
        access = _cookie_value(current, "access_token")
        assert latest != new_refresh
        other.cookies.clear()
        other.cookies.set("refresh_token", latest)
        other.cookies.set("csrf_token", csrf)
        other.cookies.set("access_token", access)
        logged_out = await other.post("/api/auth/logout", headers={"x-csrf-token": csrf})
        assert logged_out.status_code == 200, logged_out.text
        async with AsyncClient(transport=transport, base_url="http://testserver", trust_env=False) as again:
            again.cookies.set("refresh_token", latest)
            after = await again.post("/api/auth/refresh")
            assert after.status_code == 401


@pytest.mark.asyncio
async def test_access_jwt_exp_and_jwks(client, caplog):
    await _signup(client, caplog, email="jwt@example.com", name="Jwt")
    await client.get("/api/auth/confirm", params={"token": _confirm_token(caplog)})
    logged_in = await client.post(
        "/api/auth/token",
        data={"username": "jwt@example.com", "password": "password123"},
    )
    token = _cookie_value(logged_in, "access_token")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    assert header["kid"]

    jwks = await client.get("/jwks")
    well_known = await client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert well_known.json() == jwks.json()
    missing = await client.get("/jwks/kids")
    assert missing.status_code == 404

    jwk = next(key for key in jwks.json()["keys"] if key["kid"] == header["kid"])
    pem = _jwk_to_pem(jwk)
    payload = jwt.decode(token, pem, algorithms=["RS256"])
    assert payload["type"] == "access"
    assert payload["sub"]
    remaining = payload["exp"] - time.time()
    assert 14 * 60 <= remaining <= 16 * 60


@pytest.mark.asyncio
async def test_non_exempt_post_requires_csrf(client, caplog):
    open_refresh = await client.post("/api/auth/refresh")
    assert open_refresh.status_code == 401

    await _signup(client, caplog, email="csrf@example.com")
    await client.get("/api/auth/confirm", params={"token": _confirm_token(caplog)})
    logged_in = await client.post(
        "/api/auth/token",
        data={"username": "csrf@example.com", "password": "password123"},
    )
    assert logged_in.status_code == 200
    blocked = await client.post("/api/auth/logout")
    assert blocked.status_code == 403

    client.cookies.clear()
    probe = await client.post("/api/csrf-probe")
    assert probe.status_code == 403
    csrf = make_csrf_token("probe-session")
    client.cookies.set("csrf_token", csrf)
    allowed = await client.post("/api/csrf-probe", headers={"x-csrf-token": csrf})
    assert allowed.status_code == 200
    client.cookies.set("csrf_token", "other-value")
    mismatched = await client.post("/api/csrf-probe", headers={"x-csrf-token": csrf})
    assert mismatched.status_code == 403
    expired = make_csrf_token("probe-session", expires=-60)
    client.cookies.set("csrf_token", expired)
    stale = await client.post("/api/csrf-probe", headers={"x-csrf-token": expired})
    assert stale.status_code == 419


@pytest.mark.asyncio
async def test_unverified_signup_again_updates_same_user(client, caplog):
    first = await _signup(client, caplog, email="retry@example.com", password="password123", name="First")
    second = await _signup(client, caplog, email="retry@example.com", password="password456", name="Second")
    assert first["id"] == second["id"]

    await client.get("/api/auth/confirm", params={"token": _confirm_token(caplog)})
    old = await client.post(
        "/api/auth/token",
        data={"username": "retry@example.com", "password": "password123"},
    )
    assert old.status_code == 401
    new = await client.post(
        "/api/auth/token",
        data={"username": "retry@example.com", "password": "password456"},
    )
    assert new.status_code == 200
    me = await client.get("/api/auth/me")
    assert me.json()["name"] == "Second"


def _b64int(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def _jwk_to_pem(jwk: dict) -> bytes:
    public_key = RSAPublicNumbers(_b64int(jwk["e"]), _b64int(jwk["n"])).public_key()
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
