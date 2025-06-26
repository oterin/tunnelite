from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from server.components import database
from server.components.models import Tunnel, ActivationRequest, DeactivationRequest

router = APIRouter(prefix="/internal", tags=["internal"])

@router.post("/verify-activation", response_model=Tunnel)
async def verify_tunnel_activation(req: ActivationRequest):
    # 1. verify the tunnel exists and is pending
    tunnel = database.get_tunnel_by_id(req.tunnel_id)
    if not tunnel:
        raise HTTPException(status_code=404, detail="tunnel not found")
    if tunnel.get("status") != "pending":
        raise HTTPException(status_code=400, detail="tunnel is not pending")

    # 2. verify the tunnel is assigned to the requesting node
    node = database.get_node_by_secret_id(req.node_secret_id)
    if not node or node.get("public_hostname") != tunnel.get("node_public_hostname"):
         raise HTTPException(status_code=403, detail="tunnel is not assigned to this node")

    # 3. verify the api key belongs to the tunnel's owner
    user = database.find_user_by_api_key(req.api_key)
    if not user or user.get("username") != tunnel.get("owner_username"):
        raise HTTPException(status_code=403, detail="invalid api key for this tunnel")

    # 4. activate le tunnel
    if database.update_tunnel_status(req.tunnel_id, "active"):
        response_tunnel = tunnel.copy()
        response_tunnel["public_hostname"] = node.get("public_hostname")
        return response_tunnel

    raise HTTPException(status_code=500, detail="failed to update tunnel status")

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

    # authorize the request: the node making the request must own the tunnel.
    if tunnel.get("node_secret_id") != req.node_secret_id:
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
