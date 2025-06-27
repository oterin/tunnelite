import asyncio
import time
import requests
import json
import uuid
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request as FastAPIRequest, Response
from pydantic import BaseModel
from requests.models import requote_uri
import uvicorn
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import psutil
import websockets

from . import config
from .connection_manager import manager
from .proxy_server import start_tcp_listener, proxy_router

SECRET_ID_FILE = "node_secret_id.txt"
NODE_SECRET_ID = None
try:
    with open(SECRET_ID_FILE, "r") as f:
        NODE_SECRET_ID = f.read().strip()
    print(f"info:     loaded existing node secret id: {NODE_SECRET_ID}")
except FileNotFoundError:
    NODE_SECRET_ID = str(uuid.uuid4())
    with open(SECRET_ID_FILE, "w") as f:
        f.write(NODE_SECRET_ID)
    print(f"info:     generated new node secret id: {NODE_SECRET_ID}")

app = FastAPI(
    title=f"tunnelite node",
    version="0.1.0"
)

# include the new proxy router. this must be last.
app.include_router(proxy_router)

node_status = "pending"
BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024

async def heartbeat_task():
    while True:
        await asyncio.sleep(60)

        global node_status
        node_cert = get_node_cert()
        
        # get system metrics using psutil
        cpu_percent = psutil.cpu_percent()
        memory_info = psutil.virtual_memory()

        # get tunnel-specific metrics from the connection manager
        tunnel_metrics = manager.get_and_reset_metrics()

        node_details = {
            "node_secret_id": NODE_SECRET_ID,
            "public_address": config.NODE_PUBLIC_ADDRESS,
            "metrics": {
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_info.percent,
                },
                "tunnels": tunnel_metrics,
            },
        }

        try:
            print(f"info:     ({time.ctime()}) sending heartbeat...")
            
            # try jwt heartbeat first if we have a cert
            if node_cert:
                try:
                    response = requests.post(
                        f"{config.MAIN_SERVER_URL}/nodes/heartbeat",
                        json=node_details,
                        headers={"x-node-cert": node_cert}
                    )
                except requests.RequestException:
                    # fallback to old register endpoint
                    response = requests.post(
                        f"{config.MAIN_SERVER_URL}/nodes/register",
                        json=node_details
                    )
            else:
                # no cert, use old endpoint
                response = requests.post(
                    f"{config.MAIN_SERVER_URL}/nodes/register",
                    json=node_details
                )
                
            response.raise_for_status()

            response_data = response.json()
            new_status = response_data.get("status", "pending")

            if new_status != node_status:
                print(f"info:     status changed from '{node_status}' to '{new_status}'.")
                node_status = new_status

        except requests.RequestException as e:
            print(f"error:    heartbeat failed: {e}")

async def node_control_channel_task():
    while True:
        try:
            node_cert = get_node_cert()
            ws_url = config.MAIN_SERVER_URL.replace("http", "ws", 1)
            
            # use jwt endpoint if we have a cert
            if node_cert:
                control_uri = f"{ws_url}/ws/node-control-jwt?token={node_cert}"
            else:
                control_uri = f"{ws_url}/ws/node-control"
                
            print(f"info:     connecting to server control channel at {control_uri}...")
            async with websockets.connect(control_uri) as websocket:
                # only send auth message for legacy endpoint
                if not node_cert:
                    auth_payload = {"type": "auth", "node_secret_id": NODE_SECRET_ID}
                    await websocket.send(json.dumps(auth_payload))
                    
                print("info:     node control channel connected and authenticated.")

                # 2. listen for commands from the server
                async for message in websocket:
                    try:
                        command = json.loads(message)
                        if command.get("type") == "teardown_tunnel":
                            tunnel_id = command.get("tunnel_id")
                            print(f"info:     received teardown command for tunnel {tunnel_id}")
                            await manager.close_tunnel(tunnel_id)
                    except json.JSONDecodeError:
                        print("error:    received malformed command from server.")
                    except Exception as e:
                        print(f"error:    error processing command from server: {e}")

        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError) as e:
            print(f"warn:     control channel connection lost: {e}. reconnecting in 20 seconds.")
            await asyncio.sleep(20)
        except Exception as e:
            print(f"error:    an unexpected error occurred in the control channel task: {e}. reconnecting in 60 seconds.")
            await asyncio.sleep(60)


@app.on_event("startup")
def on_startup():
    # perform initial registration immediately
    register_with_main_server()

    # start background tasks
    print("info:     starting background tasks (heartbeat, control channel)...")
    asyncio.create_task(heartbeat_task())
    asyncio.create_task(node_control_channel_task())

def register_with_main_server():
    global node_status
    node_details = {
        "node_secret_id": NODE_SECRET_ID,
        "public_address": config.NODE_PUBLIC_ADDRESS,
    }
    print(f"info:     registering with main server at {config.MAIN_SERVER_URL}...")
    try:
        response = requests.post(
            f"{config.MAIN_SERVER_URL}/nodes/register",
            json=node_details
        )
        response.raise_for_status()

        response_data = response.json()
        node_status = response_data.get("status", "pending")
        print(f"info:     initial registration successful. current status: {node_status}")

    except requests.RequestException as e:
        print(f"error:    could not register with main server. {e}")

@app.get("/health")
async def health_check():
    return {"status": "ok", "node_status": node_status}

@app.get("/ping")
async def ping():
    return {"ack": "pong", "node_secret_id": NODE_SECRET_ID}

benchmark_payload_size = 10 * 1024 * 1024  # 10 mb

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
    print(f"info:     challenge listener on port {port} finished")

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
    return Response(content=bytes(benchmark_payload_size))

class TeardownRequest(BaseModel):
    tunnel_id: str

@app.post("/internal/teardown-tunnel")
async def teardown_tunnel(req: TeardownRequest):
    print(f"info:     received teardown request for tunnel {req.tunnel_id}")
    closed = await manager.close_tunnel(req.tunnel_id)
    if closed:
        return {"status": "ok", "message": "tunnel connection closed."}
    else:
        return {"status": "ok", "message": "tunnel not found or already disconnected."}


@app.websocket("/ws/connect")
async def websocket_endpoint(websocket: WebSocket):
    connection = None

    try:
        # 1. activation handshake
        message_str = await websocket.receive_text()
        message = json.loads(message_str)

        if message.get("type") != "activate":
            await websocket.close(code=1008, reason="first message must be an activation request")
            return

        tunnel_id = message.get("tunnel_id")
        api_key = message.get("api_key")

        # 2. verify with main server
        activation_payload = {
            "tunnel_id": tunnel_id,
            "api_key": api_key,
            "node_secret_id": NODE_SECRET_ID
        }
        response = requests.post(
            f"{config.MAIN_SERVER_URL}/internal/verify-activation",
            json=activation_payload
        )

        if not response.ok:
            error_detail = response.json().get("detail", "activation failed")
            await websocket.close(code=1008, reason=error_detail)
            return

        # 3. activation successful. use the authoritative data from the server
        official_tunnel_data = response.json()
        public_url = official_tunnel_data.get("public_url")
        tunnel_id = official_tunnel_data.get("tunnel_id")

        if not public_url or not tunnel_id:
            await websocket.close(code=1011, reason="server returned invalid activation response")
            return

        public_hostname = public_url.split("://")[1].split(":")[0]
        tunnel_type = official_tunnel_data.get("tunnel_type")

        connection = await manager.connect(tunnel_id, public_hostname, websocket)

        # for tcp tunnels, we need to start a dedicated listener on the assigned port
        if tunnel_type in ["tcp", "udp"]:
            try:
                port = int(public_url.split(":")[1])
                # start the listener as a background task
                tcp_task = asyncio.create_task(start_tcp_listener(tunnel_id, port))
                # store the task so we can cancel it later if the client disconnects
                connection.tcp_server_task = tcp_task
            except (ValueError, IndexError):
                await websocket.close(code=1011, reason="invalid public url format for tcp tunnel")
                return

        while True:
            # this loop keeps the client connection alive and is where
            # data forwarding from client -> public happens.
            data = await websocket.receive_bytes()
            # if it's an http tunnel, forward the response to the http proxy's response queue.
            if tunnel_type in ["http", "https"]:
                await manager.forward_to_proxy(tunnel_id, data)
            # if it's a tcp tunnel, forward it to the tcp proxy's response queue.
            elif tunnel_type in ["tcp", "udp"]:
                await manager.forward_to_proxy(tunnel_id, data)

    except WebSocketDisconnect:
        if connection:
            manager.disconnect(connection.tunnel_id)
            try:
                deactivation_payload = {"node_secret_id": NODE_SECRET_ID}
                requests.post(
                    f"{config.MAIN_SERVER_URL}/internal/tunnels/{connection.tunnel_id}/deactivate",
                    json=deactivation_payload,
                    timeout=3
                )
            except requests.RequestException as e:
                print(f"error:    failed to report deactivation for {connection.tunnel_id}: {e}")
        else:
            print("info:     client disconnected before activating a tunnel.")
    except Exception as e:
        print(f"error:    an unexpected error occurred in websocket: {e}")
        if connection and not connection.websocket.client_state.DISCONNECTED:
            await connection.websocket.close(code=1011)
            manager.disconnect(connection.tunnel_id)

def get_node_cert() -> str:
    """get node certificate from file"""
    try:
        with open("node_cert.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""
