import time
from typing import List, Optional
import requests
from fastapi import APIRouter, Request, BackgroundTasks
from pydantic import BaseModel, Field

from server.components import database

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

@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request):
    node_info_dict = node_info.model_dump()
    node_secret_id = node_info_dict["node_secret_id"]

    # check if this is the very first time we've seen this node
    existing_node = database.get_node_by_secret_id(node_secret_id)
    if not existing_node:
        # if it's new, perform geoip lookup once
        verified_ip = request.client.host
        node_info_dict["verified_ip_address"] = verified_ip
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{verified_ip}")
            geo_response.raise_for_status()
            node_info_dict["verified_geolocation"] = geo_response.json()
        except Exception as e:
            node_info_dict["verified_geolocation"] = {"error": str(e)}

    # always update the timestamp for the heartbeat
    node_info_dict["last_seen_at"] = time.time()
    database.upsert_node(node_info_dict)

    # return the current status to the node from the db
    current_node_data = database.get_node_by_secret_id(node_secret_id)
    return {
        "status": current_node_data.get("status"),
        "message": f"heartbeat received. current status: {current_node_data.get('status')}"
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
