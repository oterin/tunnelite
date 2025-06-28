import time
from typing import List, Optional
import requests
from fastapi import APIRouter, Request, Header, HTTPException, status, Query
from pydantic import BaseModel, Field

from server.components import database
from server.components.models import Node, Tunnel
from server import security

router = APIRouter(prefix="/nodes", tags=["nodes"])

class NodeInfo(BaseModel):
    node_secret_id: str
    public_address: str
    metrics: Optional[dict] = None
    last_seen_at: float = Field(default_factory=time.time)

class NodeInfoPublic(BaseModel):
    public_hostname: str
    location: str
    public_address: str

@router.get("/me", response_model=Node)
async def get_node_me(x_node_secret_id: str = Header(...)):
    """allows a node to get its own full registration record."""
    node = database.get_node_by_secret_id(x_node_secret_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found."
        )
    return node

@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request):
    incoming_data = node_info.model_dump()
    node_secret_id = incoming_data["node_secret_id"]

    # check if this is the very first time we've seen this node
    node_data = database.get_node_by_secret_id(node_secret_id)
    is_new_node = not node_data

    if is_new_node:
        # if it's new, create from the full Node model to get defaults
        node_data = Node(
            node_secret_id=node_secret_id,
            public_address=node_info.public_address
        ).model_dump()

    # update the record with the incoming data
    node_data.update(incoming_data)
    
    if is_new_node:
        # and perform geoip lookup once for new nodes
        verified_ip = request.client.host
        node_data["verified_ip_address"] = verified_ip
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{verified_ip}")
            geo_response.raise_for_status()
            node_data["verified_geolocation"] = geo_response.json()
        except Exception as e:
            node_data["verified_geolocation"] = {"error": str(e)}

    # always update the timestamp for the heartbeat
    node_data["last_seen_at"] = time.time()
    database.upsert_node(node_data)

    # return the current status to the node from the db
    current_node_data = database.get_node_by_secret_id(node_secret_id)
    return {
        "status": current_node_data.get("status", "pending"),
        "message": f"heartbeat received. current status: {current_node_data.get('status', 'pending')}"
    }

@router.get("/available", response_model=List[NodeInfoPublic])
async def get_available_nodes():
    active_nodes = database.get_active_nodes()
    public_nodes = []
    for node in active_nodes:
        # only show nodes that have an official public hostname
        if "public_hostname" in node:
            public_nodes.append({
                "public_hostname": node.get("public_hostname"),
                "location": node.get("verified_geolocation", {}).get("city", "unknown location"),
                "public_address": node.get("public_address")
            })
    return public_nodes

@router.post("/heartbeat")
async def node_heartbeat(node_info: NodeInfo, x_node_cert: str = Header(...)):
    """jwt-based heartbeat for authenticated nodes"""
    try:
        claims = security.verify(x_node_cert)
        node_secret_id = claims["sub"]
        
        # get existing node or create new one with defaults
        node_data = database.get_node_by_secret_id(node_secret_id)
        if not node_data:
            node_data = Node(
                node_secret_id=node_secret_id,
                public_address=node_info.public_address
            ).model_dump()
        
        # update with heartbeat data
        node_data.update(node_info.model_dump())
        node_data["last_seen_at"] = time.time()
        
        database.upsert_node(node_data)
        
        return {
            "status": node_data.get("status", "pending"),
            "message": f"heartbeat received via jwt. current status: {node_data.get('status', 'pending')}"
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid node certificate: {e}"
        )

@router.post("/verify-tunnel-activation", response_model=Tunnel)
async def verify_tunnel_activation(
    request: Request,
    tunnel_id: str = Query(...),
    x_node_secret_id: str = Header(...)
):
    """
    Called by a tunnel node to verify a tunnel activation request it received from a client.
    The node needs to confirm with the main server that this tunnel is legitimate.
    """
    # 1. authenticate the node
    node = database.get_node_by_secret_id(x_node_secret_id)
    if not node or node.get("status") != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="node not authorized or not active."
        )

    # 2. find the requested tunnel
    tunnel = database.get_tunnel_by_id(tunnel_id)
    if not tunnel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="tunnel not found."
        )

    # 3. verify the tunnel is pending and belongs to the calling node
    if tunnel.get("status") != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"tunnel is not in a pending state (current state: {tunnel.get('status')})."
        )
    
    if tunnel.get("node_secret_id") != node.get("node_secret_id"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tunnel is assigned to a different node."
        )

    # 4. if all checks pass, return the tunnel details to the node
    return tunnel
