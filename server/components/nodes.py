import time
from typing import List
import requests
from fastapi import APIRouter, Request, BackgroundTasks
from pydantic import BaseModel, Field

from server.components import database

router = APIRouter(prefix="/tunnelite/nodes", tags=["Nodes"])

class NodeInfo(BaseModel):
    node_id: str
    reported_location: str = Field(alias="location")
    public_address: str
    last_seen_at: float = Field(default_factory=time.time)

class NodeInfoPublic(BaseModel):
    node_id: str
    location: str
    public_address: str

@router.post("/register")
async def register_node(node_info: NodeInfo, request: Request, background_tasks: BackgroundTasks):
    node_info_dict = node_info.model_dump()
    node_id = node_info_dict["node_id"]

    # 1. gather initial verified data
    verified_ip = request.client.host # type: ignore
    node_info_dict["verified_ip_address"] = verified_ip
    node_info_dict["last_seen_at"] = time.time()

    # 2. perform geoip lookup
    # shoutout to santiago @ https://cathop.lat <3
    try:
        geo_response = requests.get(f"https://cathop.lat/api/lookup/ip/{verified_ip}")
        geo_response.raise_for_status()
        geo_data = geo_response.json()
        node_info_dict["verified_geolocation"] = geo_data

        # Attempt to get countryCode if country name is available
        if "country" in geo_data and geo_data["country"]:
            try:
                country_name = geo_data["country"]
                cc_response = requests.get(
                    "https://public.opendatasoft.com/api/explore/v2.1/catalog/datasets/countries-codes/records",
                    params={
                        "select": "iso2_code",
                        "where": f"label_en LIKE '%{country_name}%'"
                    }
                )
                cc_response.raise_for_status()
                cc_data = cc_response.json()

                if cc_data and "results" in cc_data and len(cc_data["results"]) > 0:
                    country_code = cc_data["results"][0]["iso2_code"].lower()
                    node_info_dict["verified_geolocation"]["countryCode"] = country_code
                else:
                    # No ISO2 code found for the given country name
                    if "countryCode_lookup_errors" not in node_info_dict["verified_geolocation"]:
                        node_info_dict["verified_geolocation"]["countryCode_lookup_errors"] = []
                    node_info_dict["verified_geolocation"]["countryCode_lookup_errors"].append(
                        f"No ISO2 code found for country: '{country_name}' from OpenDataSoft."
                    )

            except requests.RequestException as e:
                # Error fetching country code from public.opendatasoft.com
                if "countryCode_lookup_errors" not in node_info_dict["verified_geolocation"]:
                    node_info_dict["verified_geolocation"]["countryCode_lookup_errors"] = []
                node_info_dict["verified_geolocation"]["countryCode_lookup_errors"].append(
                    f"Country code lookup failed (OpenDataSoft): {str(e)}"
                )
            except (KeyError, IndexError) as e:
                # Error parsing JSON response for country code
                if "countryCode_lookup_errors" not in node_info_dict["verified_geolocation"]:
                    node_info_dict["verified_geolocation"]["countryCode_lookup_errors"] = []
                node_info_dict["verified_geolocation"]["countryCode_lookup_errors"].append(
                    f"Country code JSON parsing failed (OpenDataSoft): {str(e)}"
                )
        else:
            # Country name not available in the initial geolocation data
            if "countryCode_lookup_errors" not in node_info_dict["verified_geolocation"]:
                node_info_dict["verified_geolocation"]["countryCode_lookup_errors"] = []
            node_info_dict["verified_geolocation"]["countryCode_lookup_errors"].append(
                "Country name missing from initial geolocation data, cannot look up ISO2 code."
            )

    except requests.RequestException as e:
        # Initial geoip lookup from cathop.lat failed
        node_info_dict["verified_geolocation"] = {"error": str(e)}
    except Exception as e:
        # Catch any other unexpected errors during the entire geoip process
        node_info_dict["verified_geolocation"] = {"error": f"An unexpected error occurred during geoip lookup: {str(e)}"}

    # 3. upsert node data -> database
    database.upsert_node(node_info_dict)

    # 4. todo: schedule automated benchmarking
    # background_tasks.add_task(run_benchmark_for_node, node_id)

    # return the current status to the node
    current_node_data = database.get_node_by_id(node_id)
    return {
        "status": current_node_data.get("status"),
        "message": f"node '{node_id}' registered. current status: {current_node_data.get('status')}"
    }

@router.get("/available", response_model=List[NodeInfoPublic])
async def get_available_nodes():
    active_nodes = database.get_active_nodes()
    public_nodes = []
    for node in active_nodes:
        public_nodes.append({
            "node_id": node.get("node_id"),
            "location": node.get("location"),
            "public_address": node.get("public_address")
        })
    return public_nodes
