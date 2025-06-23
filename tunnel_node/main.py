import time
import requests
from fastapi import FastAPI, HTTPException
import uvicorn
import asyncio

from tunnel_node import config

app = FastAPI(
    title=f"tunnelite node - {config.NODE_ID}",
    version="0.1.0"
)

node_status = "pending"

async def heartbeat_task():
    """A background task that sends a heartbeat to the main server every 60 seconds."""
    while True:
        await asyncio.sleep(60)

        global node_status
        node_details = {
            "node_id": config.NODE_ID,
            "location": config.NODE_LOCATION,
            "public_address": config.NODE_PUBLIC_ADDRESS,
        }

        try:
            print(f"({time.ctime()}) sending heartbeat...")
            response = requests.post(
                f"{config.MAIN_SERVER_URL}/nodes/register",
                json=node_details
            )
            response.raise_for_status()

            response_data = response.json()
            new_status = response_data.get("status", "pending")

            if new_status != node_status:
                print(f"status changed from '{node_status}' to '{new_status}'.")
                node_status = new_status

        except requests.RequestException as e:
            print(f"heartbeat failed: {e}")

@app.on_event("startup")
def on_startup():
    """On startup, perform initial registration and start the heartbeat task."""
    register_with_main_server()
    print("starting heartbeat background task...")
    asyncio.create_task(heartbeat_task())

def register_with_main_server():
    """Performs a single registration attempt with the main server."""
    global node_status
    node_details = {
        "node_id": config.NODE_ID,
        "location": config.NODE_LOCATION,
        "public_address": config.NODE_PUBLIC_ADDRESS,
    }
    print(f"registering with main server at {config.MAIN_SERVER_URL}...")
    try:
        response = requests.post(
            f"{config.MAIN_SERVER_URL}/nodes/register",
            json=node_details
        )
        response.raise_for_status()

        response_data = response.json()
        node_status = response_data.get("status", "pending")
        print(f"initial registration successful. current status: {node_status}")

    except requests.RequestException as e:
        print(f"error: could not register with main server. {e}")

@app.get("/health")
async def health_check():
    """An endpoint for the main server to check node health."""
    return {"status": "ok", "node_status": node_status}

@app.get("/ping")
async def ping():
    """A simple endpoint for the client to measure latency."""
    return {"ack": "pong", "node_id": config.NODE_ID}
