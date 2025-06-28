from __future__ import generators
from hmac import trans_5C
import secrets
import time
from typing import List, Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, status, Request
from server.ratelimit import limiter
from random_word import RandomWords
from server.components.registration import parse_port_range

from server.components import database
from server.components.models import *
from server.components.auth import get_current_user
from server.components.node_control import node_manager

router = APIRouter(prefix="/tunnels", tags=["tunnels"])

def get_country_code_from_ip(ip: str) -> str:
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
        return 'us' # on failure let's just say something idk
    return 'us'

def get_available_port(node: dict) -> Optional[int]:
    try:
        port_range = parse_port_range(node.get("port_range", ""))
    except AttributeError:
        port_range = []

    if not port_range:
        return None

    # get all ports currently used by tcp/udp tunnels across ALL nodes to prevent conflicts
    active_tunnels = database.get_all_tunnels()
    used_ports = set()
    for t in active_tunnels:
        if t.get("tunnel_type") in ["tcp", "udp"] and t.get("status") in ["active", "pending"]:
            try:
                # extract port from url like "tcp://hostname:8202"
                port = int(t["public_url"].split(":")[-1])
                used_ports.add(port)
            except (IndexError, ValueError):
                continue

    # also exclude the node's main server port to prevent conflicts
    node_address = node.get("public_address", "")
    if node_address and ":" in node_address:
        try:
            main_port = int(node_address.split(":")[-1])
            used_ports.add(main_port)
        except (ValueError, IndexError):
            pass

    print(f"debug:    port allocation for node {node['node_secret_id'][:8]}: range={port_range}, used_ports={sorted(used_ports)}")

    # find a free port within the range
    for port in port_range:
        if port not in used_ports:
            print(f"debug:    allocated port {port} for tcp tunnel")
            return port

    # no free ports found
    print(f"error:    no available ports in range {port_range}, all used: {sorted(used_ports)}")
    return None

def find_best_node(tunnel_type: str, preferred_country: str, ping_data: Optional[dict] = None) -> Optional[tuple]:
    all_nodes = database.get_active_nodes()

    # filter out nodes that are under high system load
    eligible_nodes = []
    for node in all_nodes:
        metrics = node.get("metrics") or {}
        if "system" in metrics:
            # nested structure: metrics.system.cpu_percent
            system_metrics = metrics.get("system", {})
            cpu = system_metrics.get("cpu_percent", 0)
            memory = system_metrics.get("memory_percent", 0)
        else:
            # flat structure: metrics.cpu_percent
            cpu = metrics.get("cpu_percent", 0)
            memory = metrics.get("memory_percent", 0)
        
        if cpu < 90 and memory < 90:
            eligible_nodes.append(node)

    # add load information to each node
    for node in eligible_nodes:
        active_tunnels = [
            t for t in database.get_all_tunnels()
            if (
                t.get("node_secret_id") == node.get("node_secret_id") and
                t.get("status") == "active"
            )
        ]
        node["current_load"] = len(active_tunnels)
        # also add a score for sorting, lower is better
        node_metrics = node.get("metrics") or {}
        # handle both flat and nested metrics structures for scoring
        if "system" in node_metrics:
            cpu_for_score = node_metrics.get("system", {}).get("cpu_percent", 0)
        else:
            cpu_for_score = node_metrics.get("cpu_percent", 0)
        
        # incorporate ping data if available
        ping_score = 0
        if ping_data and node.get("public_hostname"):
            hostname = node["public_hostname"]
            if hostname in ping_data:
                # convert ping latency to score (lower latency = better score)
                latency_ms = ping_data[hostname]
                ping_score = min(latency_ms / 10, 50)  # cap at 50 for very high latency
        
        # weighted scoring: load (40%) + cpu (30%) + ping (30%)
        node["score"] = (node["current_load"] * 0.4) + (cpu_for_score * 0.3) + (ping_score * 0.3)
        
        # add debug info for node selection
        node["selection_debug"] = {
            "load_score": node["current_load"] * 0.4,
            "cpu_score": cpu_for_score * 0.3,
            "ping_score": ping_score * 0.3,
            "total_score": node["score"],
            "ping_ms": ping_data.get(node.get("public_hostname")) if ping_data else None
        }

    # sort nodes by score to always check the least busy ones first
    eligible_nodes.sort(key=lambda x: x["score"])

    # 1. try to find an ideal node in the preferred country
    nodes_in_country = [
        n for n in eligible_nodes
        if (
            n.get("verified_geolocation", {})
             .get("countryCode", "")
              == preferred_country
        )
    ]

    for node in nodes_in_country:
        if node["current_load"] < node.get("max_clients", 0):
            if tunnel_type in ["http", "https"]:
                return (node, None) # http tunnels dont need a port
            elif tunnel_type in ["tcp", "udp"]:
                port = get_available_port(node)
                if port:
                    return (node, port)

    # 2. fallback - find any available node if none were found in the preferred country
    for node in eligible_nodes:
        if node["current_load"] < node.get("max_clients", 0):
            if tunnel_type in ["http", "https"]:
                return (node, None)
            elif tunnel_type in ["tcp", "udp"]:
                port = get_available_port(node)
                if port:
                    return (node, port)

    # 3. no nodes available anywhere
    raise HTTPException(
        status_code=503,
        detail="the entire fucking global infrastructure is at capacity. please wait, or consider contributing a node so this won't happen again?"
    )

@router.post("", response_model=Tunnel, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/hour")
async def create_tunnel(
    request: Request,
    tunnel_request: TunnelCreate,
    current_user: dict = Depends(get_current_user),
):
    username = current_user.get("username")

    # 1. find the best node for the user
    preferred_country = get_country_code_from_ip(request.client.host) # type: ignore
    result  = find_best_node(tunnel_request.tunnel_type, preferred_country, tunnel_request.ping_data)

    if not result:
        raise HTTPException(
            status_code=503,
            detail="the entire fucking global infrastructure is at capacity. please wait, or consider contributing a node so this won't happen again?"
        )

    best_node, allocated_port = result
    node_hostname = best_node.get("public_hostname")
    if not node_hostname:
        raise HTTPException(
            status_code=503,
            detail="selected node has no public hostname"
        )

    # 2. generate a public url
    public_url = ""
    if tunnel_request.tunnel_type in ["http", "https"]:
        user_subdomain = f"{secrets.token_hex(4)}-{secrets.token_hex(2)}"
        public_url = f"http://{user_subdomain}.{node_hostname}"
    elif tunnel_request.tunnel_type in ["tcp", "udp"]:
        public_url = f"{tunnel_request.tunnel_type}://{node_hostname}:{allocated_port}"
    else:
        raise HTTPException(
            status_code=400,
            detail="invalid tunnel type"
        )

    # 3. create new tunnel and save the record
    new_tunnel_data = {
        "tunnel_id": secrets.token_hex(16),
        "owner_username": username,
        "tunnel_type": tunnel_request.tunnel_type,
        "local_port": tunnel_request.local_port,
        "public_url": public_url,
        "status": "pending",
        "created_at": time.time(),
        "node_secret_id": best_node["node_secret_id"], # internal link to the node
        "node_public_hostname": best_node["public_hostname"] # --- ADD THIS LINE ---
    }
    database.save_tunnel(new_tunnel_data)

    # construct the public-facing response model, ensuring no secret ids are exposed
    response_tunnel = new_tunnel_data.copy()
    response_tunnel["public_hostname"] = node_hostname
    del response_tunnel["node_secret_id"]

    return response_tunnel

@router.get("", response_model=List[Tunnel])
async def list_user_tunnels(current_user: dict = Depends(get_current_user)):
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=403, detail="could not validate user.")

    # create a map of node secret ids to public hostnames for efficient lookup
    nodes_map = {
        node["node_secret_id"]: node.get("public_hostname")
        for node in database.get_all_nodes()
    }

    user_tunnels_data = database.get_tunnels_by_username(username)

    # build the response, adding public_hostname and ensuring no secrets are leaked
    response_tunnels = []
    for tunnel in user_tunnels_data:
        response_tunnel = tunnel.copy()
        node_secret_id = response_tunnel.pop("node_secret_id", None)
        # Use the stored node_public_hostname if available, otherwise fall back to lookup
        response_tunnel["public_hostname"] = response_tunnel.get("node_public_hostname", nodes_map.get(node_secret_id, "unknown-node"))
        response_tunnels.append(response_tunnel)

    return response_tunnels

@router.delete("/{tunnel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tunnel(
    tunnel_id: str,
    current_user: dict = Depends(get_current_user)
):
    # allows a user to delete their own tunnel
    tunnel = database.get_tunnel_by_id(tunnel_id)
    if not tunnel:
        # if the tunnel doesn't exist, it's effectively deleted
        return

    if tunnel.get("owner_username") != current_user.get("username"):
        # users can only delete their own tunnels
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this tunnel."
        )

    database.update_tunnel_status(tunnel_id, "deleted_by_user")

    # notify the node to tear down the tunnel in real-time
    teardown_message = {
        "type": "teardown_tunnel",
        "tunnel_id": tunnel_id,
    }
    await node_manager.send_message_to_node(
        tunnel.get("node_secret_id"), teardown_message
    )

    return
