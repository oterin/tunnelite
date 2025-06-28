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