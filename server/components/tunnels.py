from _typeshed import Unused
import secrets
import time
from typing import List
from pydantic.fields import Deprecated
from typing_extensions import AnyStr

from fastapi import APIRouter, Depends, HTTPException, status

from server.components import database
from server.components.auth import get_current_user
from server.components.models import *

# router
router = APIRouter(prefix="/tunnels", tags=["tunnels"])

@router.post("", response_model=Tunnel, status_code=status.HTTP_201_CREATED)
async def create_tunnel(
    tunnel_request: TunnelCreate,
    current_user: dict = Depends(get_current_user)
):
    username = current_user.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="could not validate user"
        )

    # for now this is plenty, later on we will overcomplicate this if needed lol
    subdomain = secrets.token_hex(4)

    new_tunnel = {
        "node_id": tunnel_request.preferred_node_id,
        "tunnel_id": secrets.token_hex(16),
        "owner_username": username,
        "tunnel_type": tunnel_request.tunnel_type,
        "public_url": f"http://{subdomain}.tunnelite.local", # placeholder
        "status": "pending", # configured but not active
        "created_at": time.time(),
        "total_bandwidth_in": 0,
        "total_bandwidth_out": 0,
        "connected_clients": []
    }

    database.save_tunnel(new_tunnel)

    return Tunnel(**new_tunnel)

@router.get("", response_model=List[Tunnel])
async def list_user_tunnels(
    current_user: dict = Depends(get_current_user)
):
    username = current_user.get("username")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="could not validate user"
        )

    user_tunnels = database.get_tunnels_by_username(username)
    return user_tunnels
