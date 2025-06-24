from __future__ import generators
import secrets
import time
from typing import List, Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, status, Request
from random_word import RandomWords

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

def generate_unique_subdomain(country_code: str) -> str:
    r = RandomWords()
    for _ in range(10):
        word = r.get_random_word()
        subdomain = f"{word}.{country_code}"
        # there's no shot there's a node with this fragment
        # but if we put an infinite amount of monkeys in an
        # infinitely large room with ininite typewriters
        # eventually it is bound to create all the works of
        # shakespeare so i'd err on the side of caution 🤷🏻‍♂️
        if not any(subdomain in t.get("public_url", "") for t in database.get_all_tunnels()):
            return subdomain

    # let's fallback to a random string
    return f"{secrets.token_hex(4)}.{country_code}"

@router.post("", response_model=Tunnel, status_code=status.HTTP_201_CREATED)
async def create_tunnel(
    request: Request,
    tunnel_request: TunnelCreate,
    current_user: dict = Depends(get_current_user),
):
    username = current_user.get("username")
    client_ip = request.client.host # type: ignore

    # 1. determine user's location
    country_code = get_country_code(client_ip)
    if not country_code:
        raise HTTPException(
            status_code=500,
            detail="could not determine user location"
        )

    best_node = find_best_node_for_country(country_code)
    if not best_node:
        raise HTTPException(
            status_code=503,
            detail="the entire fucking global infrastructure is at capacity. consider adding nodes?"
        )

    # generate a unique public url for the tunnel
    subdomain = generate_unique_subdomain(country_code)
    public_url = f"http://{subdomain}.tunnelite.ws"

    new_tunnel = {
        "tunnel_id": secrets.token_hex(16),
        "owner_username": username,
        "tunnel_type": tunnel_request.tunnel_type,
        "local_port": tunnel_request.local_port,
        "public_url": public_url,
        "status": "pending",
        "created_at": time.time(),
        "node_id": best_node["node_id"],
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
