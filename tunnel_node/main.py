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
import socket
import os
from fastapi.responses import PlainTextResponse
from contextlib import asynccontextmanager

from . import config
from .connection_manager import manager, Connection
from .proxy_server import start_tcp_listener, proxy_router
from .network_logger import network_logger, NetworkEvent, NetworkEventType

SECRET_ID_FILE = "node_secret_id.txt"
NODE_SECRET_ID = None
try:
    with open(SECRET_ID_FILE, "r") as f:
        NODE_SECRET_ID = f.read().strip()
    print(f"info:     loaded existing node secret id")
except FileNotFoundError:
    NODE_SECRET_ID = str(uuid.uuid4())
    with open(SECRET_ID_FILE, "w") as f:
        f.write(NODE_SECRET_ID)
    print(f"info:     generated new node secret id")

app = FastAPI(
    title=f"tunnelite node",
    version="0.1.0"
)

node_status = "pending"
BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024

# flag to control whether background tasks should start (only in main process)
ENABLE_BACKGROUND_TASKS = os.environ.get("ENABLE_BACKGROUND_TASKS", "true").lower() == "true"

# Directory where Certbot will place challenge files
ACME_CHALLENGE_DIR = "/tmp/acme-challenges"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure the ACME challenge directory exists on startup
    os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)
    print(f"info:     ACME challenge directory prepared at {ACME_CHALLENGE_DIR}")
    
    # This is the main connection to the central server's control plane
    # It handles heartbeats and commands like 'teardown_tunnel'
    # We pass the manager instance to it so it can act on the commands
    asyncio.create_task(manager.connect_to_control_plane())
    
    yield
    # Clean up resources, if any, on shutdown
    print("info:     shutting down node server.")

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

        # use the dynamically set address or fall back to auto-detection
        public_address = config.NODE_PUBLIC_ADDRESS or f"http://{config.PUBLIC_IP}:8201"

        node_details = {
            "node_secret_id": NODE_SECRET_ID,
            "public_address": public_address,
            "metrics": {
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_info.percent,
                },
                "tunnels": tunnel_metrics,
            },
        }

        try:
            # log heartbeat event
            network_logger.log_event(NetworkEvent(
                timestamp=time.time(),
                event_type=NetworkEventType.HEARTBEAT,
                metadata={
                    "active_tunnels": tunnel_metrics['total_active_tunnels'],
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_info.percent,
                    "node_status": node_status
                }
            ))
            
            print(f"info:     ({time.ctime()}) sending heartbeat with {tunnel_metrics['total_active_tunnels']} active tunnels...")
            
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
                # log status change
                network_logger.log_event(NetworkEvent(
                    timestamp=time.time(),
                    event_type=NetworkEventType.NODE_STATUS,
                    metadata={
                        "old_status": node_status,
                        "new_status": new_status
                    }
                ))
                
                print(f"info:     status changed from '{node_status}' to '{new_status}'.")
                node_status = new_status

        except requests.RequestException as e:
            # log heartbeat error
            network_logger.log_event(NetworkEvent(
                timestamp=time.time(),
                event_type=NetworkEventType.ERROR,
                error_message=f"heartbeat failed: {e}",
                metadata={"active_tunnels": tunnel_metrics['total_active_tunnels']}
            ))
            
            print(f"error:    heartbeat failed: {e}")

async def cleanup_task():
    """background task to clean up stale connections"""
    while True:
        await asyncio.sleep(30)  # check every 30 seconds
        try:
            # cleanup connections idle for more than 5 minutes
            manager.cleanup_stale_connections(max_idle_seconds=300)
        except Exception as e:
            print(f"error:    cleanup task failed: {e}")

async def node_control_channel_task():
    retry_count = 0
    max_retries = 5

    while True:
        try:
            ws_url = config.MAIN_SERVER_URL.replace("http", "ws", 1)
            
            # WORKAROUND: connect to the api_key endpoint the server expects
            control_uri = f"{ws_url}/internal/control/ws?api_key={NODE_SECRET_ID}"
            print(f"info:     connecting to control channel (attempt {retry_count + 1})")
            print(f"debug:    control channel URI: {control_uri}")
                
            async with websockets.connect(control_uri, ssl=True) as websocket:
                print("info:     node control channel connected successfully.")
                retry_count = 0  # reset retry count on successful connection

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
            retry_count += 1
            if retry_count <= max_retries:
                backoff_time = min(10 * retry_count, 60)  # exponential backoff, max 60s
                print(f"warn:     control channel connection failed: {e}. retrying in {backoff_time}s... (attempt {retry_count}/{max_retries})")
                await asyncio.sleep(backoff_time)
            else:
                print(f"warn:     control channel failed after {max_retries} attempts. giving up for 5 minutes.")
                await asyncio.sleep(300)  # 5 minutes
                retry_count = 0
        except websockets.exceptions.InvalidHandshake as e:
            print(f"error:    control channel handshake failed: {e}. this may be a JWT issue. waiting 60 seconds.")
            await asyncio.sleep(60)
        except Exception as e:
            retry_count += 1
            print(f"error:    unexpected error in control channel (attempt {retry_count}): {e}. waiting 30 seconds.")
            await asyncio.sleep(30)


@app.on_event("startup")
async def on_startup():
    # perform initial registration immediately
    register_with_main_server()

    # start background tasks
    print("info:     starting background tasks (heartbeat, control channel, cleanup)...")
    if ENABLE_BACKGROUND_TASKS:
        asyncio.create_task(heartbeat_task())
        asyncio.create_task(cleanup_task())
    
    # wait a moment before starting control channel to let registration settle
    await asyncio.sleep(5)
    if ENABLE_BACKGROUND_TASKS:
        asyncio.create_task(node_control_channel_task())

def register_with_main_server():
    global node_status
    # use the dynamically set address or fall back to auto-detection
    public_address = config.NODE_PUBLIC_ADDRESS or f"http://{config.PUBLIC_IP}:8201"
    node_details = {
        "node_secret_id": NODE_SECRET_ID,
        "public_address": public_address,
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
    return {"status": "healthy", "node_secret_id": NODE_SECRET_ID}

@app.get("/ping")
async def ping():
    return {"message": "pong", "timestamp": time.time()}

@app.get("/debug/network-stats")
async def get_network_stats():
    """debug endpoint to get networking statistics"""
    return network_logger.get_stats()

@app.get("/debug/network-events")
async def get_network_events(count: int = 50):
    """debug endpoint to get recent network events"""
    events = network_logger.get_recent_events(count)
    return [event.to_dict() for event in events]

benchmark_payload_size = 10 * 1024 * 1024  # 10 mb

class ChallengeRequest(BaseModel):
    port: int
    key: str

def run_challenge_server(port, key):
    # create a unique handler class for this specific challenge to avoid race conditions
    class SpecificChallengeHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.end_headers()
            self.wfile.write(key.encode('utf-8'))  # use the key from closure
        def log_message(self, format, *args):
            return
    
    try:
        print(f"info:     attempting to bind challenge listener to 0.0.0.0:{port}")
        server = HTTPServer(('0.0.0.0', port), SpecificChallengeHandler)
        print(f"info:     challenge listener successfully bound to 0.0.0.0:{port} with key {key}")
        print(f"info:     waiting for challenge request on port {port}...")
        
        # set a longer timeout to handle server delays
        server.timeout = 30
        server.handle_request()
        print(f"info:     challenge listener on port {port} handled request and finished")
    except OSError as e:
        print(f"error:    failed to bind challenge listener to port {port}: {e}")
        raise  # re-raise so the API endpoint can report the error
    except Exception as e:
        print(f"error:    challenge listener on port {port} failed: {e}")
        raise  # re-raise so the API endpoint can report the error

def is_port_available(port):
    """check if a port is available for binding"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', port))
            return True
    except OSError:
        return False

@app.post("/internal/setup-challenge-listener")
async def setup_challenge_listener(req: ChallengeRequest):
    print(f"info:     setting up challenge listener on port {req.port} with key {req.key}")
    
    # check if port is available
    if not is_port_available(req.port):
        error_msg = f"port {req.port} is already in use or not available"
        print(f"error:    {error_msg}")
        raise HTTPException(status_code=400, detail=error_msg)
    
    try:
        # start the server in a separate thread
        server_thread = threading.Thread(
            target=run_challenge_server, 
            args=(req.port, req.key), 
            daemon=True,
            name=f"challenge-listener-{req.port}"
        )
        server_thread.start()
        
        # give the server a moment to start and bind
        await asyncio.sleep(1.5)
        
        # verify the thread is still alive (didn't crash immediately)
        if not server_thread.is_alive():
            raise HTTPException(status_code=500, detail=f"challenge listener thread for port {req.port} failed to start")
        
        print(f"info:     challenge listener thread started successfully for port {req.port}")
        return {"message": f"challenge listener setup completed on port {req.port}"}
        
    except Exception as e:
        error_msg = f"failed to set up challenge listener on port {req.port}: {str(e)}"
        print(f"error:    {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

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
    tunnel_id = None
    print("info:     /ws/connect endpoint entered, awaiting new connection...")
    try:
        # 1. accept the connection first!
        await websocket.accept()
        print("info:     connection accepted successfully.")
        
        # 2. activation handshake
        message_str = await websocket.receive_text()
        message = json.loads(message_str)

        if message.get("type") != "activate":
            print(f"error:    client sent wrong first message: {message}")
            await websocket.close(code=1008, reason="first message must be an activation request")
            return

        tunnel_id = message.get("tunnel_id")
        api_key = message.get("api_key")

        # 3. verify with main server
        print(f"info:     verifying activation for tunnel {tunnel_id} with main server...")
        
        activation_url = f"{config.MAIN_SERVER_URL}/nodes/verify-tunnel-activation"
        params = {"tunnel_id": tunnel_id}
        headers = {"x-node-secret-id": NODE_SECRET_ID}

        response = requests.post(activation_url, params=params, headers=headers)

        if not response.ok:
            try:
                error_detail = response.json().get("detail", "activation failed")
            except (ValueError, AttributeError):
                error_detail = f"HTTP {response.status_code}: {response.text}"
            print(f"error:    activation failed from main server: {error_detail}")
            await websocket.close(code=1008, reason=error_detail)
            return

        # 4. activation successful. use the authoritative data from the server
        try:
            official_tunnel_data = response.json()
        except ValueError as e:
            print(f"error:    failed to parse activation response as JSON: {e}")
            await websocket.close(code=1011, reason="server returned invalid activation response")
            return

        # 5. register the connection with our manager
        print(f"info:     creating tunnel connection for {tunnel_id}")
        connection = await manager.create_tunnel_connection(
            tunnel_id=tunnel_id,
            tunnel_type=official_tunnel_data["tunnel_type"],
            local_port=official_tunnel_data["local_port"],
            public_hostname=official_tunnel_data["public_hostname"],
            websocket=websocket
        )

        # 6. send activation success response
        await websocket.send_json({"status": "success", "message": "tunnel activated successfully"})
        print(f"info:     tunnel {tunnel_id} activated successfully")

        # 7. handle the tunnel traffic based on type
        if official_tunnel_data["tunnel_type"] in ["http", "https"]:
            # for http/https tunnels, we use the proxy router
            await proxy_router.handle_http_tunnel(connection)
        elif official_tunnel_data["tunnel_type"] in ["tcp", "udp"]:
            # for tcp/udp tunnels, we start a dedicated port listener
            assigned_port = official_tunnel_data.get("assigned_port")
            if not assigned_port:
                print(f"error:    no assigned port for TCP/UDP tunnel {tunnel_id}")
                await websocket.close(code=1011, reason="no assigned port for TCP/UDP tunnel")
                return
            
            print(f"info:     starting {official_tunnel_data['tunnel_type']} listener on port {assigned_port}")
            await start_tcp_listener(assigned_port, connection)

    except WebSocketDisconnect:
        print(f"info:     client disconnected from tunnel {tunnel_id}")
    except Exception as e:
        print(f"error:    unexpected error in websocket endpoint: {e}")
        try:
            await websocket.close(code=1011, reason="internal server error")
        except:
            pass
    finally:
        # cleanup: remove the connection from our manager
        if connection:
            await manager.remove_tunnel_connection(tunnel_id)
            print(f"info:     cleaned up tunnel connection {tunnel_id}")

def get_node_cert() -> str:
    """retrieves the node's certificate token for authentication"""
    try:
        with open("node_cert.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

@app.get("/internal/health")
async def health_check():
    return {"status": "ok", "node_secret_id": NODE_SECRET_ID}

@app.get("/.well-known/acme-challenge/{token}")
async def handle_acme_challenge(token: str):
    """
    Serves ACME challenge files for Let's Encrypt certificate validation.
    """
    challenge_file_path = os.path.join(ACME_CHALLENGE_DIR, token)
    
    if not os.path.exists(challenge_file_path):
        print(f"warn:     ACME challenge file not found: {challenge_file_path}")
        raise HTTPException(status_code=404, detail="Challenge file not found")
    
    try:
        with open(challenge_file_path, 'r') as f:
            content = f.read().strip()
        print(f"info:     served ACME challenge for token: {token}")
        return PlainTextResponse(content=content)
    except Exception as e:
        print(f"error:    failed to read ACME challenge file {challenge_file_path}: {e}")
        raise HTTPException(status_code=500, detail="Failed to read challenge file")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8201)
