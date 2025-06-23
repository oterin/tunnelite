import time
from typing import List

from fastapi import APIRouter, Request

from server.components.models import *
from server.components import database

router = APIRouter(prefix="/nodes", tags=["nodes"])

@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request):
    node_info_dict = node_info.model_dump()
    node_info_dict["reported_ip"] = request.client.host # type: ignore
    database.upsert_node(node_info_dict)
    return {
        "status": "success",
        "message": f"node '{node_info.node_id}' registered"
    }

@router.get("/available", response_model=List[NodeInfoPublic])
async def get_available_nodes():
    return database.get_active_nodes()
