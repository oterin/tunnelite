import secrets
import time
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from server.components import database
from server.components.auth import get_current_user

router = APIRouter(prefix="/tunnelite/tunnels", tags=["Tunnels"])

class TunnelCreate(BaseModel):
    tunnel_type: str = Field(..., description="The type of tunnel (e.g., http, tcp).")
    local_port: int = Field(..., gt=0, lt=65536, description="The local port to expose.")
    preferred_node_id: str = Field(..., description="The ID of the node selected by the client.")

@router.post("", response_model=Tunnel, status_code=status.HTTP_201_CREATED)
async def create_tunnel(
    tunnel_request: TunnelCreate,
    current_user: dict = Depends(get_current_user),
):
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=403, detail="Could not validate user.")

    subdomain = secrets.token_hex(4)

    new_tunnel = {
        "tunnel_id": secrets.token_hex(16),
        "owner_username": username,
        "tunnel_type": tunnel_request.tunnel_type,
        "local_port": tunnel_request.local_port,
        "public_url": f"http://{subdomain}.tunnelite.local",
        "status": "pending",
        "created_at": time.time(),
        "node_id": tunnel_request.preferred_node_id,
        "total_bandwidth_in": 0,
        "total_bandwidth_out": 0,
        "connected_clients": [],
    }

    database.save_tunnel(new_tunnel)

    return new_tunnel

@router.get("", response_model=List[Tunnel])
async def list_user_tunnels(current_user: dict = Depends(get_current_user)):
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=403, detail="Could not validate user.")

    user_tunnels = database.get_tunnels_by_username(username)
    return user_tunnels
