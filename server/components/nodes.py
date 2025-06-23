import time
from typing import List

import requests
from fastapi import (
    APIRouter,
    Request,
    BackgroundTasks
)

from server.components.models import *
from server.components import database

router = APIRouter(prefix="/nodes", tags=["nodes"])

@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request):
    node_info_dict = node_info.model_dump()
    node_id = node_info_dict["node_id"]

    # 1. gather initial verified data
    verified_ip = request.client.host # type: ignore
    node_info_dict["verified_ip_address"] = verified_ip
    node_info_dict["last_seen_at"] = time.time()

    # 2. perform geoip lookup
    # shoutout to santiago @ https://cathop.lat <3
    try:
        geo_response = requests.get(f"https://cathop.lat/api/lookup/ip/{verified_ip}")
        geo_response.raise_for_status()
        node_info_dict["verified_geolocation"] = geo_response.json()
    except requests.RequestException as e:
        node_info_dict["verified_geolocation"] = {"error": str(e)}

    # 3. upsert node data -> database
    database.upsert_node(node_info_dict)

    # 4. todo: schedule automated benchmarking
    # background_tasks.add_task(run_benchmark_for_node, node_id)

    # return the current status to the node
    current_node_data = database.get_node_by_id(node_id)
    return {
        "status": current_node_data.get("status"),
        "message": f"node '{node_id}' registered. current status: {current_node_data.get('status')}"
    }

@router.get("/available", response_model=List[NodeInfoPublic])
async def get_available_nodes():
    return database.get_active_nodes()
