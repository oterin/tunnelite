import os
import requests
from typing import List, Dict, Any

# load your main domain and api keys from config/environment variables
# ensure these are in your config file or environment
SPACESHIP_API_KEY = os.environ.get("SPACESHIP_API_KEY")
SPACESHIP_API_SECRET = os.environ.get("SPACESHIP_API_SECRET")
BASE_DOMAIN = os.environ.get("TUNNELITE_DOMAIN", "tunnelite.ws")

API_BASE_URL = "https://spaceship.dev/api/v1"

def update_node_a_record(hostname: str, ip_address: str) -> bool:
    """
    Updates the A record for a given node hostname using the Spaceship API.
    This function performs a safe update by fetching existing records,
    modifying only the target record, and putting the full list back.
    API Docs: https://docs.spaceship.dev/#tag/DNS-records/operation/saveRecords
    """
    if not all([SPACESHIP_API_KEY, SPACESHIP_API_SECRET, BASE_DOMAIN]):
        print("error:    Spaceship API credentials or base domain not configured.")
        return False

    # The "name" for the API is the subdomain part (e.g., "node-us-1")
    if not hostname.endswith(BASE_DOMAIN):
        print(f"error:    Hostname {hostname} does not belong to base domain {BASE_DOMAIN}.")
        return False
    
    # Use '@' for the apex domain, otherwise just the subdomain part
    name = hostname.replace(f".{BASE_DOMAIN}", "")
    if name == BASE_DOMAIN:
        name = "@"
    
    headers = {
        "X-API-Key": SPACESHIP_API_KEY,
        "X-API-Secret": SPACESHIP_API_SECRET,
    }

    try:
        # 1. Get all existing records to avoid accidentally deleting them
        # Note: Spaceship's API is paginated. For simplicity, this assumes 
        # you have fewer than 500 records. Increase 'take' if needed.
        get_url = f"{API_BASE_URL}/dns/records/{BASE_DOMAIN}?take=500&skip=0"
        res = requests.get(get_url, headers=headers, timeout=15)
        res.raise_for_status()
        records = res.json().get("items", [])

        # 2. Filter out any old A records for this specific hostname
        # The API requires a list of dictionaries for the request body
        updated_records: List[Dict[str, Any]] = [
            r for r in records
            if not (r.get("type") == "A" and r.get("name") == name)
        ]

        # 3. Add the new A record for our node
        new_record = {
            "type": "A",
            "name": name,
            "address": ip_address,
            "ttl": 300 # A low TTL is good for dynamic IPs
        }
        updated_records.append(new_record)
        
        # We need to format the body to match the API specification,
        # which expects a list of records.
        request_body = updated_records

        # 4. Put the entire new list of records back
        put_url = f"{API_BASE_URL}/dns/records/{BASE_DOMAIN}"
        res = requests.put(put_url, headers=headers, json=request_body, timeout=15)
        res.raise_for_status()

        print(f"info:     Successfully updated A record for {hostname} to {ip_address}")
        return True

    except requests.RequestException as e:
        print(f"error:    Failed to update DNS record for {hostname}: {e}")
        if e.response:
            print(f"error details: {e.response.text}")
        return False
    except Exception as e:
        print(f"error:    An unexpected error occurred in DNS update: {e}")
        return False