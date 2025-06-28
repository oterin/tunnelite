import secrets
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.security import APIKeyHeader, OAuth2PasswordRequestForm

from server.ratelimit import limiter

import bcrypt
bcrypt.__about__ = bcrypt # type: ignore

from passlib.context import CryptContext
from pydantic import BaseModel

from server.components import database
from server.components.models import *
from server.components.bans import check_ban, get_client_ip

from server.config import get as get_config

import jwt

# configuration
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# router setup
router = APIRouter(prefix="/auth", tags=["authentication"])

# helper functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# api key dependency with ban checking
async def get_current_user(request: Request = None, api_key: str = Depends(api_key_header)) -> Dict:
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

    # check for bans if request context is available
    if request:
        client_ip = get_client_ip(request)
        ban_check = check_ban(
            ip_address=client_ip,
            username=user["username"],
            user_id=user.get("user_id")
        )
        
        if ban_check.is_banned and ban_check.ban_scope.value == "service":
            raise HTTPException(
                status_code=403,
                detail=f"account banned - {ban_check.ban_type.value}: {ban_check.reason}"
            )

    return user

# helper function for getting user from api key with ban checking
async def get_user_from_api_key(request: Request, api_key: str = Depends(api_key_header)) -> Dict:
    """get user from api key with comprehensive ban checking"""
    return await get_current_user(request, api_key)

# node api key dependency
async def get_node_from_api_key(request: Request) -> Dict:
    """authenticate a node using x-api-key header (node secret id)"""
    api_key = request.headers.get("x-api-key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="x-api-key header required",
        )

    node = database.get_node_by_secret_id(api_key)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid node credentials",
        )

    return node

async def get_node_from_token(
    websocket: WebSocket,
    token: str = Query(None)
) -> Dict:
    """authenticate a node via jwt in query param"""
    if token is None:
        raise WebSocketDisconnect(code=1008, reason="token not provided")

    try:
        payload = jwt.decode(
            token,
            get_config("JWT_SECRET"),
            algorithms=["HS256"]
        )
        node_secret_id = payload.get("sub")
        if node_secret_id is None:
            raise WebSocketDisconnect(code=1008, reason="invalid token")

        # check role
        if payload.get("role") != "node":
            raise WebSocketDisconnect(code=1008, reason="invalid role")

        node = database.get_node_by_secret_id(node_secret_id)
        if not node:
            raise WebSocketDisconnect(code=1008, reason="node not found")

        return node

    except jwt.InvalidTokenError as e:
        raise WebSocketDisconnect(code=1008, reason=f"invalid token: {e}")

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
