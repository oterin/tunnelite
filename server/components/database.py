"""
tunnelite db component
"""

import json
import os
import time
from typing import Dict, Optional, List
from filelock import FileLock, BaseFileLock

# cry harder im not using sqlite3
# nor postgres nor any other db shut up
USER_DB_FILE = "users.jsonl"
TUNNEL_DB_FILE = "tunnels.jsonl"
NODE_DB_FILE = "nodes.jsonl"

# Helper to get a lock for a given file
def _get_file_lock(file_path: str) -> BaseFileLock:
    return FileLock(f"{file_path}.lock", timeout=10)

def find_user_by_username(username: str) -> Optional[Dict]:
    with _get_file_lock(USER_DB_FILE):
        if not os.path.exists(USER_DB_FILE):
            return None
        with open(USER_DB_FILE, 'r') as f:
            for line in f:
                if not line.strip(): continue
                user_data = json.loads(line)
                if user_data.get("username") == username:
                    return user_data
    return None

def find_user_by_api_key(api_key: str) -> Optional[Dict]:
    with _get_file_lock(USER_DB_FILE):
        if not os.path.exists(USER_DB_FILE):
            return None
        with open(USER_DB_FILE, 'r') as f:
            for line in f:
                if not line.strip(): continue
                user_data = json.loads(line)
                if user_data.get("api_key") == api_key:
                    return user_data
    return None

def save_user(user_data: Dict) -> None:
    users = []
    user_found = False
    with _get_file_lock(USER_DB_FILE):
        if os.path.exists(USER_DB_FILE):
            with open(USER_DB_FILE, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    existing_user = json.loads(line)
                    if existing_user.get("username") == user_data.get("username"):
                        users.append(user_data) # Update existing user
                        user_found = True
                    else:
                        users.append(existing_user)

        if not user_found:
            users.append(user_data)

        with open(USER_DB_FILE, 'w') as f:
            for user in users:
                f.write(json.dumps(user) + '\n')

# tunnel management
def save_tunnel(tunnel_data: Dict) -> None:
    with _get_file_lock(TUNNEL_DB_FILE):
        with open(TUNNEL_DB_FILE, 'a') as f:
            f.write(json.dumps(tunnel_data) + '\n')

def get_tunnels_by_username(username: str) -> List[Dict]:
    tunnels = []
    with _get_file_lock(TUNNEL_DB_FILE):
        if not os.path.exists(TUNNEL_DB_FILE):
            return []
        with open(TUNNEL_DB_FILE, 'r') as f:
            for line in f:
                if not line.strip(): continue
                tunnel_data = json.loads(line)
                if tunnel_data.get("owner_username") == username:
                    tunnels.append(tunnel_data)
    return tunnels

# node management yaay
def upsert_node(node_data: Dict):
    nodes = []
    with _get_file_lock(NODE_DB_FILE):
        if os.path.exists(NODE_DB_FILE):
            with open(NODE_DB_FILE, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    nodes.append(json.loads(line))

        node_id_to_find = node_data.get("node_id")
        found_node_index = -1
        for i, existing_node in enumerate(nodes):
            if existing_node.get("node_id") == node_id_to_find:
                found_node_index = i
                break

        if found_node_index != -1:
            node_to_update = nodes[found_node_index]
            for key, value in node_data.items():
                if value is not None:
                    node_to_update[key] = value
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
    nodes = []
    updated = False
    with _get_file_lock(NODE_DB_FILE):
        # Read all nodes if the file exists
        if os.path.exists(NODE_DB_FILE):
            with open(NODE_DB_FILE, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    nodes.append(json.loads(line))

        for i, node in enumerate(nodes):
            if node.get("node_id") == node_id:
                nodes[i]["status"] = status
                updated = True
                break

        if updated:
            with open(NODE_DB_FILE, 'w') as f:
                for node in nodes:
                    f.write(json.dumps(node) + '\n')
    return updated

def get_all_nodes() -> List[Dict]:
    nodes = []
    with _get_file_lock(NODE_DB_FILE):
        if not os.path.exists(NODE_DB_FILE):
            return []
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

def get_tunnel_by_id(tunnel_id: str) -> Optional[Dict]:
    with _get_file_lock(TUNNEL_DB_FILE):
        if not os.path.exists(TUNNEL_DB_FILE):
            return None
        with open(TUNNEL_DB_FILE, 'r') as f:
            for line in f:
                if not line.strip(): continue
                tunnel_data = json.loads(line)
                if tunnel_data.get("tunnel_id") == tunnel_id:
                    return tunnel_data
    return None

def update_tunnel_status(tunnel_id: str, status: str) -> bool:
    tunnels = []
    updated = False
    with _get_file_lock(TUNNEL_DB_FILE):
        if os.path.exists(TUNNEL_DB_FILE):
            with open(TUNNEL_DB_FILE, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    tunnels.append(json.loads(line))

        for i, tunnel in enumerate(tunnels):
            if tunnel.get("tunnel_id") == tunnel_id:
                tunnels[i]["status"] = status
                updated = True
                break

        if updated:
            with open(TUNNEL_DB_FILE, 'w') as f:
                for tunnel in tunnels:
                    f.write(json.dumps(tunnel) + '\n')
    return updated

def get_all_tunnels() -> List[Dict]:
    """Retrieves all tunnels from the database."""
    tunnels = []
    with _get_file_lock(TUNNEL_DB_FILE):
        if os.path.exists(TUNNEL_DB_FILE):
            with open(TUNNEL_DB_FILE, "r") as f:
                for line in f:
                    if not line.strip(): continue
                    tunnels.append(json.loads(line))
    return tunnels
