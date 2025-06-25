from fastapi import APIRouter, HTTPException, status
from requests.models import HTTPError

from server.components import database
from server.components.models import *

router = APIRouter(prefix="/tunnelite/internal", tags=["Internal"])

@router.post("/verify-activation")
async def verify_tunnel_activation(req: ActivationRequest):
    # 1. verify the tunnel exists and is pending
    tunnel = database.get_tunnel_by_id(req.tunnel_id)
    if not tunnel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="tunnel not found"
        )
    if tunnel.get("status") != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"tunnel is not pending. status is '{tunnel.get('status')}'"
        )

    # 2. verify the tunnel is assigned to the requesting node
    if tunnel.get("node_id") != req.node_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tunnel is not assigned to the requesting node"
        )

    # 3. verify the api key belongs to the tunnel's owner
    user = database.find_user_by_api_key(req.api_key)
    if not user or user.get("username") != tunnel.get("owner_username"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="api key non-existent or not relevant"
        )

    # 4. activate le tunnel
    if database.update_tunnel_status(req.tunnel_id, "active"):
        return {
            "status": "ok",
            "message": "tunnel activated"
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to activate tunnel"
        )

@router.post("/tunnels/{tunnel_id}/deactivate")
async def deactivate_tunnel(
    tunnel_id: str,
    req: DeactivationRequest
):
    # 1. verify the tunnel exists and the node is legitimate
    tunnel = database.get_tunnel_by_id(tunnel_id)
    if not tunnel:
        return {
            "status": "ok",
            "message": "tunnel already deleted or never existed"
        }

    if tunnel.get("node_id") != req.node_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="node is not authorized to modify this tunnel"
        )

    # 2. update the status to 'inactive' (instead of deleting to preserve history)
    if database.update_tunnel_status(tunnel_id, "inactive"):
        return {
            "status": "ok",
            "message": "tunnel deactivated"
        }

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="failed to update tunnel status"
    )
