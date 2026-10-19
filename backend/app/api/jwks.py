from fastapi import APIRouter

from app.services.auth_service import public_jwks

router = APIRouter()


@router.get("/jwks")
async def jwks() -> dict:
    return public_jwks()


@router.get("/.well-known/jwks.json")
async def jwks_well_known() -> dict:
    return public_jwks()
