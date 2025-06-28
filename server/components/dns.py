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

API_BASE_URL = "https://api.cloudflare.com/client/v4"

def get_zone_id_for_domain(domain: str) -> str:
    """
    Automatically discover the zone ID for a given domain using the Cloudflare API.
    This is useful when the zone ID in the config is incorrect or outdated.
    """
    if not CLOUDFLARE_API_TOKEN:
        print("error:    No Cloudflare API token available")
        return None
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }
    
    try:
        # list all zones and find the one matching our domain
        zones_url = f"{API_BASE_URL}/zones"
        params = {"name": domain}
        
        print(f"debug:    Looking up zone ID for domain: {domain}")
        res = requests.get(zones_url, headers=headers, params=params, timeout=15)
        
        if res.status_code != 200:
            print(f"error:    Failed to list zones. Status: {res.status_code}")
            print(f"error:    Response: {res.text}")
            return None
        
        zones_data = res.json()
        zones = zones_data.get("result", [])
        
        if not zones:
            print(f"error:    No zone found for domain {domain}")
            return None
        
        zone_id = zones[0]["id"]
        zone_name = zones[0]["name"]
        print(f"info:     Found zone ID {zone_id} for domain {zone_name}")
        return zone_id
        
    except Exception as e:
        print(f"error:    Failed to lookup zone ID: {e}")
        return None

def update_node_a_record(hostname: str, ip_address: str) -> bool:
    """
    Updates the A record for a given node hostname using the Cloudflare API.
    This function finds existing records and updates them, or creates new ones.
    API Docs: https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record
    """
    if not CLOUDFLARE_API_TOKEN:
        print("error:    Cloudflare API token not configured.")
        return False

    # the "name" for cloudflare is the full hostname (e.g., "node-us-1.tunnelite.ws")
    if not hostname.endswith(BASE_DOMAIN):
        print(f"error:    Hostname {hostname} does not belong to base domain {BASE_DOMAIN}.")
        return False
    
    # get the correct zone ID for the base domain
    zone_id = get_zone_id_for_domain(BASE_DOMAIN)
    if not zone_id:
        print(f"error:    Could not determine zone ID for domain {BASE_DOMAIN}")
        return False
    
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json",
    }

    try:

        # 1. check if a record already exists for this hostname
        list_url = f"{API_BASE_URL}/zones/{zone_id}/dns_records"
        params = {
            "type": "A",
            "name": hostname
        }
        
        print(f"debug:    Checking for existing record: {list_url} with params {params}")
        res = requests.get(list_url, headers=headers, params=params, timeout=15)
        
        if res.status_code != 200:
            print(f"error:    Failed to list DNS records. Status: {res.status_code}")
            print(f"error:    Response: {res.text}")
            return False
            
        response_data = res.json()
        existing_records = response_data.get("result", [])
        print(f"debug:    Found {len(existing_records)} existing records for {hostname}")

        if existing_records:
            # 2. update the existing record
            record_id = existing_records[0]["id"]
            update_url = f"{API_BASE_URL}/zones/{zone_id}/dns_records/{record_id}"
            
            update_data = {
                "type": "A",
                "name": hostname,
                "content": ip_address,
                "ttl": 300  # low ttl for dynamic ips
            }
            
            print(f"debug:    Updating existing record {record_id} to {ip_address}")
            res = requests.put(update_url, headers=headers, json=update_data, timeout=15)
            
            if res.status_code != 200:
                print(f"error:    Failed to update DNS record. Status: {res.status_code}")
                print(f"error:    Response: {res.text}")
                return False
            
            print(f"info:     Successfully updated existing A record for {hostname} to {ip_address}")
        else:
            # 3. create a new record
            create_url = f"{API_BASE_URL}/zones/{zone_id}/dns_records"
            
            create_data = {
                "type": "A",
                "name": hostname,
                "content": ip_address,
                "ttl": 300  # low ttl for dynamic ips
            }
            
            print(f"debug:    Creating new record for {hostname} -> {ip_address}")
            res = requests.post(create_url, headers=headers, json=create_data, timeout=15)
            
            if res.status_code not in [200, 201]:
                print(f"error:    Failed to create DNS record. Status: {res.status_code}")
                print(f"error:    Response: {res.text}")
                return False
            
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