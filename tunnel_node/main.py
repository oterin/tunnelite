import time
import requests
from fastapi import FastAPI, HTTPException
import uvicorn

from tunnel_node import config

app = FastAPI(
    title=f"tunnelite node - {config.NODE_ID}",
    version="0.1.0"
)

@app.on_event("startup")
def register_with_main_server():
    node_details = {
        "node_id": config.NODE_ID,
        "location": config.NODE_LOCATION,
        "public_address": config.NODE_PUBLIC_ADDRESS,
        "last_seen_at": time.time()
    }
    print(f"registering with the main server at {config.MAIN_SERVER_URL}...")
    try:
        response = requests.post(f"{config.MAIN_SERVER_URL}/nodes", json=node_details)
        response.raise_for_status()
        print(f"registered with the main server")
    except requests.RequestException as e:
        print(f"failed to register with the main server: {e}")

@app.get("/ping")
async def ping():
    return {"ack": "pong", "node_id": config.NODE_ID}

@app.get("/status")
async def status():
    return {"status": "ok"}
