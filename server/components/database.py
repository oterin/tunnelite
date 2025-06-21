"""
tunnelite db component
"""

import json
import os
from typing import Dict, Optional

DB_FILE = "users.jsonl" # cry harder im not using sqlite3
                        # nor postgres nor any other db shut up

def _ensure_db_file_exists() -> None:
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, 'w') as f: pass

def find_user_by_username(username: str) -> Optional[Dict]:
    _ensure_db_file_exists()
    with open(DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): pass
            user_data = json.loads(line)
            if user_data.get("username") == username:
                return user_data
    return None

def find_user_by_api_key(api_key: str) -> Optional[Dict]:
    _ensure_db_file_exists()
    with open(DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): pass
            user_data = json.loads(line)
            if user_data.get("api_key") == api_key:
                return user_data
    return None

def save_user(user_data: Dict) -> None:
    _ensure_db_file_exists()
    users = []
    with open(DB_FILE, 'r') as f:
        for line in f:
            if not line.strip(): continue
            existing_user = json.loads(line)
            if existing_user.get("username") == user_data.get("username"):
                users.append(user_data)
            else:
                users.append(existing_user)

    with open(DB_FILE, 'w') as f:
        for user in users:
            f.write(json.dumps(user) + '\n')
