import time
from typing import List
import requests
from fastapi import APIRouter, Request, BackgroundTasks
from pydantic import BaseModel, Field # Make sure Field is imported

from . import database

router = APIRouter(prefix="/tunnelite/nodes", tags=["Nodes"])

# --- Pydantic Models (Updated) ---
class NodeInfo(BaseModel):
    node_id: str
    # Use an alias to accept "location" from the JSON payload
    # but use "reported_location" in our code.
    reported_location: str = Field(alias="location")
    public_address: str
    last_seen_at: float = Field(default_factory=time.time)

class NodeInfoPublic(BaseModel):
    node_id: str
    location: str # This can remain 'location' for public display
    public_address: str


# --- API Endpoints ---
@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request, background_tasks: BackgroundTasks):
    # Pydantic v2 automatically handles the alias, so node_info.dict()
    # will have a 'reported_location' key.
    # We use by_alias=True to get the original key names for the database.
    node_info_dict = node_info.dict(by_alias=True)

    # ... (rest of the function is the same as before) ...
    node_id = node_info_dict["node_id"]

    verified_ip = request.client.host
    node_info_dict["verified_ip_address"] = verified_ip
    node_info_dict["last_seen_at"] = time.time()

    if verified_ip == "127.0.0.1":
        node_info_dict["verified_geolocation"] = {"status": "success", "city": "localhost"}
    else:
        try:
            geo_response = requests.get(f"http://ip-api.com/json/{verified_ip}")
            geo_response.raise_for_status()
            node_info_dict["verified_geolocation"] = geo_response.json()
        except requests.RequestException as e:
            node_info_dict["verified_geolocation"] = {"error": str(e)}

    database.upsert_node(node_info_dict)

    current_node_data = database.get_node_by_id(node_id)
    return {
        "status": current_node_data.get("status"),
        "message": f"Node '{node_id}' registered. Current status: {current_node_data.get('status')}"
    }

@router.get("/available", response_model=List[NodeInfoPublic])
async def get_available_nodes():
    """Endpoint for clients to discover active Tunnel Nodes."""
    active_nodes = database.get_active_nodes()
    # Manually map the field name for the public response
    public_nodes = []
    for node in active_nodes:
        public_nodes.append({
            "node_id": node.get("node_id"),
            "location": node.get("location"), # The original key name
            "public_address": node.get("public_address")
        })
    return public_nodes
