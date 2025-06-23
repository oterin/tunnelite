import os
from typing import List

from fastapi import (
    APIRouter,
    Security,
    HTTPException,
    status,
    Depends
)

from fastapi.security import APIKeyHeader

from server.components import database
from server.components.models import *
from pydantic import BaseModel, Field

from dotenv import load_dotenv
load_dotenv()

ADMIN_API_KEY = os.getenv("TUNNELITE_ADMIN_KEY")
if not ADMIN_API_KEY:
    raise ValueError("TUNNELITE_ADMIN_KEY environment variable is not set")

api_key_header = APIKeyHeader(
    name="X-Admin-Key",
    auto_error=False
)

async def get_admin_api_key(
    key: str = Security(api_key_header)
):
    if key == ADMIN_API_KEY:
        return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing admin key"
    )

router = APIRouter(
    prefix="/tunnelite/admin",
    tags=["admin"],
    dependencies=[Depends(get_admin_api_key)]
)

@router.get("/nodes", response_model=List[Node])
async def list_all_nodes():
    return database.get_all_nodes()

@router.post(
    "/nodes/{node_id}/approve",
    status_code=status.HTTP_200_OK
)
async def approve_node(node_id: str) -> dict:
    node = database.get_node_by_id(node_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )

    if database.update_node_status(node_id, "approved"):
        return {
            "message": f"node '{node_id}' approved"
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to approve node"
    )

@router.post(
    "/nodes/{node_id}/disable",
    status_code=status.HTTP_200_OK
)
async def disable_node(node_id: str) -> dict:
    node = database.get_node_by_id(node_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )

    if database.update_node_status(node_id, "disabled"):
        return {
            "message": f"node '{node_id}' disabled"
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to disable node"
    )
