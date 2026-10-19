import base64
import hashlib
import hmac
import os
import time
from typing import Tuple

from fastapi import HTTPException, Request, status

from app.constants import HTTP_AUTHENTICATION_TIMEOUT

SECRET = os.getenv("CSRF_SECRET", "").strip()
if not SECRET:
    raise RuntimeError("CSRF_SECRET must be set")


def make_csrf_token(session_id: str, expires: int = 3600) -> str:
    payload = f"{session_id}|{int(time.time()) + expires}"
    sig = hmac.new(SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload.encode("utf-8") + b"." + sig).decode("ascii")


def _equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def verify_csrf_token(token: str) -> Tuple[str, bool, bool]:
    """Return ``(session_id, ok, expired)``.

    The session id is returned to the caller and is not logged.
    """
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        # The signature is raw SHA-256 (32 bytes) and may itself contain 0x2e.
        # The separator is the single byte immediately before that suffix.
        if len(raw) < 33 or raw[-33:-32] != b".":
            return "", False, False
        payload, sig = raw[:-33], raw[-32:]
        expected = hmac.new(SECRET.encode("utf-8"), payload, hashlib.sha256).digest()
        if not _equal(expected, sig):
            return "", False, False
        session_id, exp = payload.decode("utf-8").rsplit("|", 1)
        if int(exp) < int(time.time()):
            return session_id, False, True
        return session_id, True, False
    except Exception:
        return "", False, False


async def verify_csrf(request: Request) -> None:
    header = request.headers.get("x-csrf-token")
    cookie = request.cookies.get("csrf_token")
    if not header or not cookie:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF verification failed empty token")

    _, ok, expired = verify_csrf_token(header)
    if expired:
        raise HTTPException(status_code=HTTP_AUTHENTICATION_TIMEOUT, detail="CSRF verification failed expired token")
    if not ok:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF verification failed invalid token")
    if not _equal(header.encode("utf-8"), cookie.encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF verification failed token mismatch")
