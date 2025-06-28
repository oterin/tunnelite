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
from server import config



# load config from values.json or env
ADMIN_API_KEY = config.get("TUNNELITE_ADMIN_KEY")
if not ADMIN_API_KEY:
    raise ValueError("TUNNELITE_ADMIN_KEY not configured")

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
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(get_admin_api_key)]
)

@router.get("/nodes", response_model=List[Node])
async def list_all_nodes():
    return database.get_all_nodes()

@router.get("/nodes/pending", response_model=List[Node])
async def list_pending_nodes():
    """returns a list of all nodes with 'pending' status."""
    all_nodes = database.get_all_nodes()
    return [node for node in all_nodes if node.get("status") == "pending"]

@router.post(
    "/nodes/{node_secret_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Approve a pending node"
)
async def approve_node(node_secret_id: str) -> dict:
    """approves a node, changing its status from 'pending' to 'active'."""
    node = database.get_node_by_secret_id(node_secret_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )
    
    if node.get("status") != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"node is not in 'pending' state (current state: {node.get('status')})"
        )

    if database.update_node_status(node["node_secret_id"], "active"):
        return {
            "message": f"node with secret id '{node_secret_id[:8]}...' has been approved and is now active."
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to approve node"
    )

@router.post(
    "/nodes/{node_secret_id}/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable an active node"
)
async def disable_node(node_secret_id: str) -> dict:
    """disables a node, changing its status to 'disabled'."""
    node = database.get_node_by_secret_id(node_secret_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )

    if database.update_node_status(node["node_secret_id"], "disabled"):
        return {
            "message": f"node '{node.get('public_hostname', node_secret_id[:8])}' disabled"
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to disable node"
    )
