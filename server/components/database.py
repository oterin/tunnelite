"""
tunnelite db component
"""

import json
import os
import time
from typing import Dict, Optional, List

# cry harder im not using sqlite3
# nor postgres nor any other db shut up
USER_DB_FILE = "users.jsonl"
TUNNEL_DB_FILE = "tunnels.jsonl"
NODE_DB_FILE = "nodes.jsonl"

def _ensure_db_file_exists(file_path) -> None:
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f: pass

def find_user_by_username(username: str) -> Optional[Dict]:
    _ensure_db_file_exists(USER_DB_FILE)
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            user_data = json.loads(line)
            if user_data.get("username") == username:
                return user_data
    return None

def find_user_by_api_key(api_key: str) -> Optional[Dict]:
    _ensure_db_file_exists(USER_DB_FILE)
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            user_data = json.loads(line)
            if user_data.get("api_key") == api_key:
                return user_data
    return None

def save_user(user_data: Dict) -> None:
    _ensure_db_file_exists(USER_DB_FILE)
    users = []
    user_found = False
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            existing_user = json.loads(line)
            if existing_user.get("username") == user_data.get("username"):
                users.append(user_data)
                user_found = True
            else:
                users.append(existing_user)

    if not user_found:
        users.append(user_data)

    with open(USER_DB_FILE, 'w') as f:
        for user in users:
            f.write(json.dumps(user) + '\n')

# tunnel mangnegnemtn
def save_tunnel(tunnel_data: Dict) -> None:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    with open(TUNNEL_DB_FILE, 'a') as f:
        f.write(json.dumps(tunnel_data) + '\n')

def get_tunnels_by_username(username: str) -> List[Dict]:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    tunnels = []
    with open(TUNNEL_DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            tunnel_data = json.loads(line)
            if tunnel_data.get("owner_username") == username:
                tunnels.append(tunnel_data)
    return tunnels

# node management yaay
def upsert_node(node_data: Dict):
    _ensure_db_file_exists(NODE_DB_FILE)
    nodes = get_all_nodes()

    node_id_to_find = node_data.get("node_id")
    found_node_index = -1
    for i, existing_node in enumerate(nodes):
        if existing_node.get("node_id") == node_id_to_find:
            found_node_index = i
            break

    if found_node_index != -1:
        node_to_update = nodes[found_node_index]
        node_to_update['last_seen_at'] = node_data.get('last_seen_at')
        node_to_update['verified_ip_address'] = node_data.get('verified_ip_address')
        node_to_update['verified_geolocation'] = node_data.get('verified_geolocation')

    else:
        node_data["status"] = "pending"
        nodes.append(node_data)

    with open(NODE_DB_FILE, "w") as f:
        for node in nodes:
            f.write(json.dumps(node) + "\n")

def get_node_by_id(node_id: str) -> Optional[Dict]:
    nodes = get_all_nodes()
    for node in nodes:
        if node.get("node_id") == node_id:
            return node
    return None

def update_node_status(node_id: str, status: str) -> bool:
    nodes = get_all_nodes()
    updated = False
    for i, node in enumerate(nodes):
        if node.get("node_id") == node_id:
            nodes[i]["status"] = status
            updated = True

    if updated:
        with open(NODE_DB_FILE, 'w') as f:
            for node in nodes:
                f.write(json.dumps(node) + '\n')
    return updated

def get_all_nodes() -> List[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)
    nodes = []
    with open(NODE_DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            node_data = json.loads(line)
            nodes.append(node_data)

    return nodes

def get_active_nodes() -> List[Dict]:
    all_nodes = get_all_nodes()
    active_nodes = []

    # if da node didnt erport uthath is u hactive in 2 mintues, it dead gng
    two_minutes_ago = time.time() - 120

    for node in all_nodes:
        if (
            node.get("last_seen_at", 0) > two_minutes_ago
            and node.get("status") == "approved"
        ):
            active_nodes.append(node)

    return active_nodes
