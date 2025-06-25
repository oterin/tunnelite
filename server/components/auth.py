

import secrets
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import APIKeyHeader, OAuth2PasswordRequestForm

from server.ratelimit import limiter

import bcrypt
bcrypt.__about__ = bcrypt # type: ignore

from passlib.context import CryptContext
from pydantic import BaseModel

from server.components import database
from server.components.models import *

# configuration
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# router setup
router = APIRouter(prefix="/tunnelite/auth", tags=["Authentication"])

# helper functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# api key dependency
async def get_current_user(api_key: str = Depends(api_key_header)) -> Dict:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
            headers={"www-authenticate": "bearer"},
        )

    user = database.find_user_by_api_key(api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
            headers={"www-authenticate": "bearer"},
        )

    return user

# api endpoints
@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")
async def register_user(user: UserCreate, request: Request) -> Dict:
    existing_user = database.find_user_by_username(user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="username already exists",
        )

    hashed_password = get_password_hash(user.password)
    api_key = secrets.token_hex(32)

    new_user = {
        "username": user.username,
        "password": hashed_password,
        "api_key": api_key,
    }
    database.save_user(new_user)

    return {"message": "user registered successfully"}

@router.post("/token", response_model=Token)
@limiter.limit("10/minute")
async def login_for_api_key(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
    user = database.find_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"www-authenticate": "bearer"},
        )

    return Token(api_key=user["api_key"])

@router.patch("/token", response_model=Token)
@limiter.limit("5/minute")
async def refresh_api_key(request: Request, current_user: Dict = Depends(get_current_user)) -> Token:
    new_api_key = secrets.token_hex(32)
    current_user["api_key"] = new_api_key
    database.save_user(current_user)

    return Token(api_key=new_api_key)

@router.get("/users/me", response_model=User)

async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user
