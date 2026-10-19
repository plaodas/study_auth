from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.services import token_service

ALGORITHM = "RS256"


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    return int(raw)


def _read_configured_pem(value_name: str, path_name: str) -> str | None:
    value = os.getenv(value_name, "").strip()
    if value:
        return value.replace("\\n", "\n")
    path = os.getenv(path_name, "").strip()
    if not path:
        return None
    try:
        data = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"{path_name} could not be read: {path}") from exc
    if not data.strip():
        raise RuntimeError(f"{path_name} is empty: {path}")
    return data


def _kid_for_public_key(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _public_key_from_pem(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def _kid_for_public_pem(pem_str: str) -> str:
    return _kid_for_public_key(_public_key_from_pem(pem_str))


def _kid_from_private(priv_pem: str) -> str:
    private_key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
    return _kid_for_public_key(private_key.public_key())


def _load_public_keys(public_pem: str | None) -> Dict[str, str]:
    keys: Dict[str, str] = {}
    if public_pem:
        keys[_kid_for_public_pem(public_pem)] = public_pem
    use_dir = os.getenv("JWT_USE_KEYS_DIR", "0").lower() in ("1", "true", "yes")
    directory = os.getenv("JWT_PUBLIC_KEYS_DIR", "").strip()
    if use_dir and directory and os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            try:
                pem = Path(path).read_text(encoding="utf-8")
                keys[_kid_for_public_pem(pem)] = pem
            except Exception:
                continue
    return keys


PRIVATE_KEY = _read_configured_pem("JWT_PRIVATE_KEY", "JWT_PRIVATE_KEY_PATH")
PUBLIC_KEY = _read_configured_pem("JWT_PUBLIC_KEY", "JWT_PUBLIC_KEY_PATH")
_PUBLIC_KEYS = _load_public_keys(PUBLIC_KEY)
USE_KEYS_DIR = os.getenv("JWT_USE_KEYS_DIR", "0").lower() in ("1", "true", "yes")

if not PRIVATE_KEY or not _PUBLIC_KEYS:
    raise RuntimeError(
        "Set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH, and JWT_PUBLIC_KEY or "
        "JWT_PUBLIC_KEY_PATH. With JWT_USE_KEYS_DIR=1, JWT_PUBLIC_KEYS_DIR can supply public keys."
    )

SIGNING_KID = _kid_from_private(PRIVATE_KEY)
if SIGNING_KID not in _PUBLIC_KEYS:
    raise RuntimeError("The JWT private key does not match any configured public key")

ACCESS_TOKEN_EXPIRE_MINUTES = _env_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
REFRESH_TOKEN_EXPIRE_DAYS = _env_int("REFRESH_TOKEN_EXPIRE_DAYS", 7)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def coerce_user_pk(raw_id):
    if raw_id is None or isinstance(raw_id, uuid.UUID):
        return raw_id
    try:
        return uuid.UUID(str(raw_id))
    except ValueError:
        return raw_id


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def authenticate_user(db: AsyncSession, email: str, password: str) -> Optional[User]:
    user = (await db.execute(select(User).where(User.email == email))).scalars().first()
    if user is None or not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    # python-jose treats naive datetimes as local time via utctimetuple().
    lifetime = expires_delta if expires_delta is not None else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": datetime.now(timezone.utc) + lifetime, "type": "access"})
    return jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM, headers={"kid": SIGNING_KID})


def decode_access_token(token: str) -> dict:
    """Validate an access JWT. The ``kid`` header selects the public key."""
    try:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception:
            kid = None
        if kid and kid in _PUBLIC_KEYS:
            pub_pem = _PUBLIC_KEYS[kid]
        else:
            pub_pem = next(iter(_PUBLIC_KEYS.values()))
        payload = jwt.decode(
            token,
            pub_pem,
            algorithms=[ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except JWTError:
        raise credentials_exception
    return payload


def _get_token_from_request(request: Request, bearer: str | None = Depends(oauth2_scheme)) -> str:
    if bearer:
        return bearer
    access_token = request.cookies.get("access_token")
    if access_token:
        return access_token
    raise credentials_exception


async def create_refresh_token(
    db: AsyncSession,
    user_id: int | uuid.UUID | str,
    expires_delta: Optional[timedelta] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    if expires_delta is None:
        expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return await token_service.create_token(
        db,
        user_id=user_id,
        token_type="refresh",
        expires_delta=expires_delta,
        ip=ip,
        user_agent=user_agent,
    )


async def verify_refresh_token(db: AsyncSession, raw_token: str | None):
    return await token_service.verify_and_consume_token(db, raw_token, token_type="refresh")


async def get_current_user(
    token: str = Depends(_get_token_from_request),
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        payload = decode_access_token(token)
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception from None
    if payload.get("type") != "access" or payload.get("sub") is None:
        raise credentials_exception
    user = await db.get(User, coerce_user_pk(payload.get("sub")))
    if user is None or not getattr(user, "mail_verified", False):
        raise credentials_exception
    return user


def jwk_for_pem(pem: str, kid: str) -> dict:
    public_key = _public_key_from_pem(pem)
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("only RSA public keys are published")
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": ALGORITHM,
        "n": _int_to_base64url(numbers.n),
        "e": _int_to_base64url(numbers.e),
    }


def _int_to_base64url(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_jwks() -> dict:
    keys = []
    for kid, pem in _PUBLIC_KEYS.items():
        try:
            keys.append(jwk_for_pem(pem, kid))
        except Exception:
            continue
    return {"keys": keys}
