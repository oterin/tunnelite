import json
import os
import time
from typing import Dict, Optional, List
from filelock import FileLock

USER_DB_FILE = "users.jsonl"
TUNNEL_DB_FILE = "tunnels.jsonl"
NODE_DB_FILE = "nodes.jsonl"
TELEMETRY_DB_FILE = "telemetry.jsonl"
TUNNEL_EVENTS_DB_FILE = "tunnel_events.jsonl"
BANS_DB_FILE = "bans.jsonl"

def _ensure_db_file_exists(db_file: str):
    if not os.path.exists(db_file):
        with open(db_file, "w") as f:
            pass

def get_value(key: str, default=None):
    _ensure_db_file_exists(BANS_DB_FILE)
    lock = FileLock(f"{BANS_DB_FILE}.lock")
    with lock:
        with open(BANS_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if record.get("key") == key:
                        return record.get("value", default)
    return default

def set_value(key: str, value):
    _ensure_db_file_exists(BANS_DB_FILE)
    records = []
    found = False
    lock = FileLock(f"{BANS_DB_FILE}.lock")
    with lock:
        with open(BANS_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if record.get("key") == key:
                        records.append({"key": key, "value": value, "timestamp": time.time()})
                        found = True
                    else:
                        records.append(record)
        
        if not found:
            records.append({"key": key, "value": value, "timestamp": time.time()})
        
        with open(BANS_DB_FILE, "w") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

def delete_key(key: str):
    _ensure_db_file_exists(BANS_DB_FILE)
    records = []
    lock = FileLock(f"{BANS_DB_FILE}.lock")
    with lock:
        with open(BANS_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if record.get("key") != key:
                        records.append(record)
        
        with open(BANS_DB_FILE, "w") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")

def list_keys(prefix: str = "") -> List[str]:
    _ensure_db_file_exists(BANS_DB_FILE)
    keys = []
    lock = FileLock(f"{BANS_DB_FILE}.lock")
    with lock:
        with open(BANS_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    key = record.get("key", "")
                    if key.startswith(prefix):
                        keys.append(key)
    return keys

def find_user_by_username(username: str) -> Optional[Dict]:
    _ensure_db_file_exists(USER_DB_FILE)
    lock = FileLock(f"{USER_DB_FILE}.lock")
    with lock:
        with open(USER_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    user_data = json.loads(line)
                    if user_data.get("username") == username:
                        return user_data
    return None

def find_user_by_api_key(api_key: str) -> Optional[Dict]:
    _ensure_db_file_exists(USER_DB_FILE)
    lock = FileLock(f"{USER_DB_FILE}.lock")
    with lock:
        with open(USER_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    user_data = json.loads(line)
                    if user_data.get("api_key") == api_key:
                        return user_data
    return None

def save_user(user_data: Dict) -> None:
    _ensure_db_file_exists(USER_DB_FILE)
    users = []
    user_found = False
    lock = FileLock(f"{USER_DB_FILE}.lock")
    with lock:
        with open(USER_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
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

def save_tunnel(tunnel_data: Dict) -> None:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    lock = FileLock(f"{TUNNEL_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_DB_FILE, 'a') as f:
            f.write(json.dumps(tunnel_data) + '\n')

def get_tunnels_by_username(username: str) -> List[Dict]:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    tunnels = []
    lock = FileLock(f"{TUNNEL_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    tunnel_data = json.loads(line)
                    if tunnel_data.get("owner_username") == username:
                        tunnels.append(tunnel_data)
    return tunnels

def get_tunnel_by_id(tunnel_id: str) -> Optional[Dict]:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    lock = FileLock(f"{TUNNEL_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    tunnel = json.loads(line)
                    if tunnel.get("tunnel_id") == tunnel_id:
                        return tunnel
    return None

def update_tunnel_status(tunnel_id: str, status: str) -> bool:
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    tunnels = []
    updated = False
    lock = FileLock(f"{TUNNEL_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
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
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    tunnels = []
    lock = FileLock(f"{TUNNEL_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    tunnels.append(json.loads(line))
    return tunnels

def upsert_node(node_data: Dict):
    _ensure_db_file_exists(NODE_DB_FILE)
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        nodes = get_all_nodes(locked=True)
        node_secret_id = node_data.get("node_secret_id")
        found = False
        for i, existing_node in enumerate(nodes):
            if existing_node.get("node_secret_id") == node_secret_id:
                nodes[i].update(node_data)
                found = True
                break
        if not found:
            if "status" not in node_data:
                node_data["status"] = "pending"
            nodes.append(node_data)

        with open(NODE_DB_FILE, "w") as f:
            for node in nodes:
                f.write(json.dumps(node) + "\n")

def get_node_by_id(node_id: str) -> Optional[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        with open(NODE_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    node = json.loads(line)
                    if node.get("node_id") == node_id:
                        return node
    return None

def get_node_by_secret_id(node_secret_id: str) -> Optional[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        with open(NODE_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    node = json.loads(line)
                    if node.get("node_secret_id") == node_secret_id:
                        return node
    return None

def get_node_by_hostname(public_hostname: str) -> Optional[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        with open(NODE_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    node = json.loads(line)
                    if node.get("public_hostname") == public_hostname:
                        return node
    return None

def update_node_status(node_secret_id: str, status: str) -> bool:
    _ensure_db_file_exists(NODE_DB_FILE)
    nodes = []
    updated = False
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        with open(NODE_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    nodes.append(json.loads(line))

        for i, node in enumerate(nodes):
            if node.get("node_secret_id") == node_secret_id:
                nodes[i]["status"] = status
                updated = True
                break

        if updated:
            with open(NODE_DB_FILE, 'w') as f:
                for node in nodes:
                    f.write(json.dumps(node) + '\n')
    return updated

def get_all_nodes(locked: bool = False) -> List[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)

    def _read_nodes():
        nodes = []
        with open(NODE_DB_FILE, "r") as f:
            for line in f:
                if line.strip():
                    nodes.append(json.loads(line))
        return nodes

    if locked:
        return _read_nodes()
    else:
        lock = FileLock(f"{NODE_DB_FILE}.lock")
        with lock:
            return _read_nodes()

def get_active_nodes() -> List[Dict]:
    all_nodes = get_all_nodes()
    active_nodes = []

    # if the node didnt report that it is active in 2 minutes, it is dead
    two_minutes_ago = time.time() - 120

    for node in all_nodes:
        if (
            node.get("last_seen_at", 0) > two_minutes_ago
            and node.get("status") == "approved"
        ):
            active_nodes.append(node)

    return active_nodes

def store_telemetry(telemetry_record: Dict) -> None:
    _ensure_db_file_exists(TELEMETRY_DB_FILE)
    lock = FileLock(f"{TELEMETRY_DB_FILE}.lock")
    with lock:
        if "timestamp" not in telemetry_record:
            telemetry_record["timestamp"] = time.time()
        
        with open(TELEMETRY_DB_FILE, 'a') as f:
            f.write(json.dumps(telemetry_record) + '\n')

def get_telemetry_for_node(node_secret_id: str, since_timestamp: float) -> List[Dict]:
    _ensure_db_file_exists(TELEMETRY_DB_FILE)
    telemetry_records = []
    lock = FileLock(f"{TELEMETRY_DB_FILE}.lock")
    with lock:
        with open(TELEMETRY_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if (record.get("node_secret_id") == node_secret_id and 
                        record.get("timestamp", 0) >= since_timestamp):
                        telemetry_records.append(record)
    return telemetry_records

def get_latest_telemetry_for_node(node_secret_id: str) -> Optional[Dict]:
    _ensure_db_file_exists(TELEMETRY_DB_FILE)
    latest_record = None
    latest_timestamp = 0
    lock = FileLock(f"{TELEMETRY_DB_FILE}.lock")
    with lock:
        with open(TELEMETRY_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    if (record.get("node_secret_id") == node_secret_id and 
                        record.get("timestamp", 0) > latest_timestamp):
                        latest_record = record
                        latest_timestamp = record.get("timestamp", 0)
    
    return latest_record

def store_tunnel_event(event_record: Dict) -> None:
    _ensure_db_file_exists(TUNNEL_EVENTS_DB_FILE)
    lock = FileLock(f"{TUNNEL_EVENTS_DB_FILE}.lock")
    with lock:
        if "timestamp" not in event_record:
            event_record["timestamp"] = time.time()
        
        with open(TUNNEL_EVENTS_DB_FILE, 'a') as f:
            f.write(json.dumps(event_record) + '\n')

def get_tunnel_events_for_node(node_secret_id: str, since_timestamp: float, event_type: Optional[str] = None) -> List[Dict]:
    _ensure_db_file_exists(TUNNEL_EVENTS_DB_FILE)
    events = []
    lock = FileLock(f"{TUNNEL_EVENTS_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_EVENTS_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if (event.get("node_secret_id") == node_secret_id and 
                        event.get("timestamp", 0) >= since_timestamp):
                        if event_type is None or event.get("event_type") == event_type:
                            events.append(event)
    return events

def count_tunnel_events_for_node(node_secret_id: str, since_timestamp: float) -> int:
    _ensure_db_file_exists(TUNNEL_EVENTS_DB_FILE)
    count = 0
    lock = FileLock(f"{TUNNEL_EVENTS_DB_FILE}.lock")
    with lock:
        with open(TUNNEL_EVENTS_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)
                    if (event.get("node_secret_id") == node_secret_id and 
                        event.get("timestamp", 0) >= since_timestamp):
                        count += 1
    return count

def get_nodes_by_owner(username: str) -> List[Dict]:
    _ensure_db_file_exists(NODE_DB_FILE)
    nodes = []
    lock = FileLock(f"{NODE_DB_FILE}.lock")
    with lock:
        with open(NODE_DB_FILE, 'r') as f:
            for line in f:
                if line.strip():
                    node = json.loads(line)
                    if node.get("owner_username") == username:
                        nodes.append(node)
    return nodes

def initialize_database():
    _ensure_db_file_exists(USER_DB_FILE)
    _ensure_db_file_exists(TUNNEL_DB_FILE)
    _ensure_db_file_exists(NODE_DB_FILE)
    _ensure_db_file_exists(TELEMETRY_DB_FILE)
    _ensure_db_file_exists(TUNNEL_EVENTS_DB_FILE)
    _ensure_db_file_exists(BANS_DB_FILE)
