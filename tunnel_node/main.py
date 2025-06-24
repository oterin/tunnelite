import time
import requests
import json
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request as FastAPIRequest, Response
from pydantic import BaseModel
import uvicorn
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import config

app = FastAPI(
    title=f"tunnelite node - {config.NODE_ID}",
    version="0.1.0"
)

node_status = "pending"

async def heartbeat_task():
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
    register_with_main_server()
    print("starting heartbeat background task...")
    asyncio.create_task(heartbeat_task())

def register_with_main_server():
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
    return {"status": "ok", "node_status": node_status}

@app.get("/ping")
async def ping():
    return {"ack": "pong", "node_id": config.NODE_ID}

BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

class ChallengeHandler(BaseHTTPRequestHandler):
    challenge_key = "default_key"
    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.end_headers()
        self.wfile.write(self.challenge_key.encode('utf-8'))
    def log_message(self, format, *args):
        return

class ChallengeRequest(BaseModel):
    port: int
    key: str

def run_challenge_server(port, key):
    handler = ChallengeHandler
    handler.challenge_key = key
    server = HTTPServer(('', port), handler)
    server.handle_request()
    print(f"challenge listener on port {port} finished")

@app.post("/internal/setup-challenge-listener")
async def setup_challenge_listener(req: ChallengeRequest):
    server_thread = threading.Thread(target=run_challenge_server, args=(req.port, req.key), daemon=True)
    server_thread.start()
    return {"message": f"challenge listener setup initiated on port {req.port}"}

@app.post("/internal/run-benchmark")
async def benchmark_post(request: FastAPIRequest):
    body = await request.body()
    return Response(content=f"received {len(body)} bytes")

@app.get("/internal/run-benchmark")
async def benchmark_get():
    return Response(content=bytes(BENCHMARK_PAYLOAD_SIZE))
