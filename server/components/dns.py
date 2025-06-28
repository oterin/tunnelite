import os
import requests
from typing import List, Dict, Any

# load cloudflare api keys and base domain from server/dns_secrets.json
import json

secrets_path = os.path.join(os.path.dirname(__file__), "..", "dns_secrets.json")
try:
    with open(secrets_path, "r") as f:
        _dns_secrets = json.load(f)
        CLOUDFLARE_API_TOKEN = _dns_secrets.get("CLOUDFLARE_API_TOKEN")
        CLOUDFLARE_ZONE_ID = _dns_secrets.get("CLOUDFLARE_ZONE_ID")
        BASE_DOMAIN = _dns_secrets.get("BASE_DOMAIN", "tunnelite.ws")
except Exception as e:
    print(f"error:    could not load dns_secrets.json: {e}")
    CLOUDFLARE_API_TOKEN = None
    CLOUDFLARE_ZONE_ID = None
    BASE_DOMAIN = "tunnelite.ws"

API_BASE_URL = "https://api.cloudflare.com/v4"

def update_node_a_record(hostname: str, ip_address: str) -> bool:
    """
    Updates the A record for a given node hostname using the Cloudflare API.
    This function finds existing records and updates them, or creates new ones.
    API Docs: https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record
    """
    if not all([CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID, BASE_DOMAIN]):
        print("error:    Cloudflare API credentials or zone ID not configured.")
        return False

    # the "name" for cloudflare is the full hostname (e.g., "node-us-1.tunnelite.ws")
    if not hostname.endswith(BASE_DOMAIN):
        print(f"error:    Hostname {hostname} does not belong to base domain {BASE_DOMAIN}.")
        return False
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        # 1. first, check if a record already exists for this hostname
        list_url = f"{API_BASE_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
        params = {
            "type": "A",
            "name": hostname
        }
        
        res = requests.get(list_url, headers=headers, params=params, timeout=15)
        res.raise_for_status()
        existing_records = res.json().get("result", [])

        if existing_records:
            # 2. update the existing record
            record_id = existing_records[0]["id"]
            update_url = f"{API_BASE_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record_id}"
            
            update_data = {
                "type": "A",
                "name": hostname,
                "content": ip_address,
                "ttl": 300  # low ttl for dynamic ips
            }
            
            res = requests.put(update_url, headers=headers, json=update_data, timeout=15)
            res.raise_for_status()
            
            print(f"info:     Successfully updated existing A record for {hostname} to {ip_address}")
        else:
            # 3. create a new record
            create_url = f"{API_BASE_URL}/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
            
            create_data = {
                "type": "A",
                "name": hostname,
                "content": ip_address,
                "ttl": 300  # low ttl for dynamic ips
            }
            
            res = requests.post(create_url, headers=headers, json=create_data, timeout=15)
            res.raise_for_status()
            
            print(f"info:     Successfully created new A record for {hostname} to {ip_address}")

        return True

    except requests.RequestException as e:
        print(f"error:    Failed to update DNS record for {hostname}: {e}")
        if hasattr(e, 'response') and e.response:
            try:
                error_details = e.response.json()
                print(f"error details: {error_details}")
            except:
                print(f"error details: {e.response.text}")
        return False
    except Exception as e:
        print(f"error:    An unexpected error occurred in DNS update: {e}")
        return False