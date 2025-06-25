from __future__ import generators
import secrets
import time
from typing import List, Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, status, Request
from random_word import RandomWords
from server.components.registration import parse_port_range

from server.components import database
from server.components.models import *
from server.components.auth import get_current_user

router = APIRouter(prefix="/tunnelite/tunnels", tags=["Tunnels"])

def get_country_code(ip: str) -> Optional[str]:
    if ip == "127.0.0.1": return "local"
    try:
        res = requests.get(f"https://cathop.lat/api/lookup/ip/{ip}")
        cc = requests.get(
            "https://public.opendatasoft.com/api/explore/v2.1/catalog/datasets/countries-codes/records",
            params={
                "select": "iso2_code",
                "where": f"label_en LIKE '%{res.json()['country']}%'"
            }
        )
        return cc.json()["results"][0]["iso2_code"].lower()
    except requests.RequestException:
        return None

def find_best_node_for_country(country_code: str) -> Optional[dict]:
    all_nodes = database.get_active_nodes()

    # 1. filter by user's countruy
    candidate_nodes = [
        node for node in all_nodes
        if node.get("verified_geolocation", {}).get("countryCode", "") == country_code
    ]

    if not candidate_nodes: candidate_nodes = all_nodes

    # 2. grab the telemetry so we can sell your soul to oracle
    for node in candidate_nodes:
        active_tunnels = [t for t in database.get_all_tunnels() if t.get("node_id") == node.get("node_id") and t.get("status") == "active"]
        node["current_load"] = len(active_tunnels)

    # 3. filter nodes that are at capacity
    eligible_nodes = [
        node for node in candidate_nodes
        if node["current_load"] < node.get("max_clients", 0)
    ]

    if not eligible_nodes:
        # we're fucked.
        return None

    # sort by lowest current load and return the best one
    eligible_nodes.sort(key=lambda n: n["current_load"])
    return eligible_nodes[0]

def get_available_tcp_port(node: dict) -> Optional[int]:
    try:
        port_range = parse_port_range(node.get("port_range", ""))
    except AttributeError:
        port_range = []

    if not port_range:
        return None

    # get all ports currently used by tcp/udp tunnels
    active_tunnels = database.get_all_tunnels()
    used_ports = set()
    for t in active_tunnels:
        if t.get("node_id") == node["node_id"] and t.get("tunnel_type") in ["tcp", "udp"]:
            try:
                port = int(t["public_url"].split(":")[1])
                used_ports.add(port)
            except (IndexError, ValueError):
                continue

    # find a free port within the range
    for port in port_range:
        if port not in used_ports:
            return port

    # no free ports found, rip in pieces.
    return None

@router.post("", response_model=Tunnel, status_code=status.HTTP_201_CREATED)
async def create_tunnel(
    request: Request,
    tunnel_request: TunnelCreate,
    current_user: dict = Depends(get_current_user),
):
    username = current_user.get("username")

    # 1. find the best node for the user
    country_code = get_country_code_from_ip(request.client.host) # type: ignore
    best_node = find_best_node_for_country(country_code)
    if not best_node:
        raise HTTPException(
            status_code=503,
            detail="the entire fucking global infrastructure is at capacity. please wait, or consider contributing a node so this won't happen again?"
        )

    node_hostname = best_node.get("public_hostname")
    if not node_hostname:
        raise HTTPException(
            status_code=500,
            detail="the selected node doesn't have a public hostname. how? idk. please contact support."
        )

    # 2. generate the correct public url based on tunnel type
    public_url = ""
    if tunnel_request.tunnel_type in ["http", "https"]:
        # unique user-facing subdomain on the hostname of the node
        user_subdomain = f"{secrets.token_hex(4)}-{secrets.token_hex(2)}"
        public_url = f"{tunnel_request.tunnel_type}://{user_subdomain}.{node_hostname}"
    elif tunnel_request.tunnel_type in ["tcp", "udp"]:
        # unique port :)
        port = get_available_tcp_port(best_node)
        if not port:
            raise HTTPException(
                status_code=503,
                detail=f"node '{best_node['id']}' is at capacity. please wait, or consider contributing a node so this won't happen again?"
            )
        public_url = f"{tunnel_request.tunnel_type}://{node_hostname}:{port}"
    else:
        raise HTTPException(
            status_code=400,
            detail="invalid tunnel type"
        )

    # 3. create and save the new tunnel record
    new_tunnel = {
        "tunnel_id": secrets.token_hex(16),
        "owner_username": username,
        "tunnel_type": tunnel_request.tunnel_type,
        "local_port": tunnel_request.local_port,
        "public_url": public_url,
        "status": "pending",
        "created_at": time.time(),
        "node_id": best_node["node_id"]
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
