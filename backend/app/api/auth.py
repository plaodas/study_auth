import os
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import app.auth as auth
import app.services.token_service as token_service
from app.db.session import get_db
from app.models.user import User
from app.services.csrf import make_csrf_token
from app.services.email import confirmation_url, send_confirmation_email

router = APIRouter(prefix="/auth", tags=["auth"])

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")


class SignupPayload(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    name: str = Field(min_length=1)


def _client_meta(request: Request) -> tuple[Optional[str], Optional[str]]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip: Optional[str] = forwarded.split(",")[0].strip()
    elif request.client is not None and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = None
    return client_ip, request.headers.get("user-agent")


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
) -> None:
    access_max_age = int(auth.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    refresh_max_age = int(auth.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=access_max_age,
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=refresh_max_age,
        path="/",
    )
    response.set_cookie(
        "csrf_token",
        csrf_token,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=access_max_age,
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie("access_token", path="/", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
    response.delete_cookie("refresh_token", path="/", secure=COOKIE_SECURE, httponly=True, samesite=COOKIE_SAMESITE)
    response.delete_cookie("csrf_token", path="/", secure=COOKIE_SECURE, httponly=False, samesite=COOKIE_SAMESITE)


async def _issue_session(response: Response, request: Request, db: AsyncSession, user: User) -> dict:
    access_token = auth.create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    client_ip, user_agent = _client_meta(request)
    refresh_token = await auth.create_refresh_token(
        db,
        user.id,
        expires_delta=timedelta(days=auth.REFRESH_TOKEN_EXPIRE_DAYS),
        ip=client_ip,
        user_agent=user_agent,
    )
    csrf_token = make_csrf_token(str(user.id))
    _set_auth_cookies(response, access_token, refresh_token, csrf_token)
    return {"token_type": "bearer"}


@router.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(payload: SignupPayload, request: Request, db: AsyncSession = Depends(get_db)):
    existing = (await db.execute(select(User).where(User.email == payload.email))).scalars().first()
    if existing is not None:
        if existing.mail_verified:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
        existing.hashed_password = auth.get_password_hash(payload.password)
        existing.name = payload.name
        existing.is_active = True
        db.add(existing)
        await db.commit()
        await db.refresh(existing)
        user = existing
    else:
        user = User(
            name=payload.name,
            email=payload.email,
            hashed_password=auth.get_password_hash(payload.password),
            is_active=True,
            mail_verified=False,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    client_ip, user_agent = _client_meta(request)
    raw = await token_service.create_token(
        db,
        user.id,
        token_type="verify",
        expires_delta=timedelta(hours=24),
        ip=client_ip,
        user_agent=user_agent,
    )
    await send_confirmation_email(user.email, user.name, confirmation_url(raw))
    return {"id": user.id, "email": user.email}


@router.get("/confirm")
async def confirm_email(token: str, db: AsyncSession = Depends(get_db)):
    verified = await token_service.verify_and_consume_token(db, token, token_type="verify")
    if verified is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    user = await db.get(User, auth.coerce_user_pk(verified.user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.mail_verified = True
    db.add(user)
    await db.commit()
    return {"status": "ok", "message": "Email confirmed"}


@router.post("/token")
async def login_for_access_token(
    response: Response,
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    existing = (await db.execute(select(User).where(User.email == form_data.username))).scalars().first()
    if existing is not None and not existing.mail_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    user = await auth.authenticate_user(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="メールアドレスまたはパスワードが正しくありません",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await _issue_session(response, request, db, user)


@router.post("/refresh")
async def refresh_access_token(
    response: Response,
    request: Request,
    refresh_token: Optional[str] = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
):
    verified = await auth.verify_refresh_token(db, refresh_token)
    if verified is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    user = await db.get(User, auth.coerce_user_pk(verified.user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not user.mail_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    return await _issue_session(response, request, db, user)


@router.post("/logout")
async def logout(
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(auth.get_current_user),
):
    await token_service.revoke_all_user_tokens(db, current_user.id)
    _clear_auth_cookies(response)
    return {"status": "ok"}


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(auth.get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "name": current_user.name,
        "mail_verified": bool(current_user.mail_verified),
    }
