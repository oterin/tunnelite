import asyncio
import json
import os
import ssl
import sys
import uuid
import time
import socket
from multiprocessing import Process, cpu_count
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from urllib.parse import urlparse, urlunparse

import requests
import uvicorn
import websockets
from tunnel_node import config

# these imports are now relative to the project root
from tunnel_node.main import app as fastapi_app

# --- url configuration and normalization ---
# shared config helper
from server import config as common_config

# read the main server url from config
RAW_MAIN_SERVER_URL = common_config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")
MAIN_SERVER_URL = RAW_MAIN_SERVER_URL

# admin key for registration
ADMIN_API_KEY = common_config.get("TUNNELITE_ADMIN_KEY")

# constants for the node
SECRET_ID_FILE = "node_secret_id.txt"
BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 mb
CERT_TOKEN_FILE = "node_cert.txt"
KEY_FILE = None  # will be set dynamically
CERT_FILE = None  # will be set dynamically
DROP_TO_USER = None  # optional privilege dropping
DROP_TO_GROUP = None  # optional privilege dropping

async def get_public_ip():
    """uses a third-party service to determine the node's public ip address."""
    try:
        print("info:     fetching public ip address...")
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        response.raise_for_status()
        ip = response.json()["ip"]
        print(f"info:     public ip address is {ip}")
        return ip
    except requests.RequestException as e:
        print(f"error:    could not fetch public ip: {e}")
        return None

async def request_ssl_certificate_from_server(public_ip: str):
    """
    request ssl certificate generation from the server.
    the server handles all dns challenges and cloudflare api calls.
    """
    print("info:     requesting ssl certificate generation from server...")
    
    node_secret_id = get_node_secret_id()
    headers = {"x-api-key": node_secret_id}
    payload = {"public_ip": public_ip}
    
    try:
        response = requests.post(
            f"{MAIN_SERVER_URL}/internal/control/generate-ssl-certificate",
            json=payload,
            headers=headers,
            timeout=300,  # 5 minutes timeout for certificate generation
            verify=True
        )
        response.raise_for_status()
        
        cert_data = response.json()
        if cert_data.get("status") != "success":
            print(f"error:    server ssl certificate generation failed: {cert_data}")
            return None
        
        # save certificates locally
        hostname = cert_data.get("hostname")
        ssl_cert = cert_data.get("ssl_certificate")
        ssl_key = cert_data.get("ssl_private_key")
        
        if not all([hostname, ssl_cert, ssl_key]):
            print("error:    server response missing required certificate data")
            return None
        
        # create directories if they don't exist
        cert_dir = f"/etc/letsencrypt/live/{hostname}"
        os.makedirs(cert_dir, mode=0o755, exist_ok=True)
        
        cert_path = f"{cert_dir}/fullchain.pem"
        key_path = f"{cert_dir}/privkey.pem"
        
        # write certificate files with secure permissions
        with open(cert_path, 'w') as f:
            f.write(ssl_cert)
        os.chmod(cert_path, 0o644)
        
        with open(key_path, 'w') as f:
            f.write(ssl_key)
        os.chmod(key_path, 0o600)  # private key should be read-only by root
        
        print(f"info:     ssl certificate saved to {cert_path}")
        print(f"info:     ssl private key saved to {key_path}")
        
        return {
            "hostname": hostname,
            "cert_path": cert_path,
            "key_path": key_path
        }
        
    except requests.RequestException as e:
        print(f"error:    failed to request ssl certificate from server: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_detail = e.response.json()
                print(f"error:    server error details: {error_detail}")
            except:
                print(f"error:    server response: {e.response.text}")
        return None
    except Exception as e:
        print(f"error:    unexpected error during ssl certificate request: {e}")
        return None

async def get_self_node_record():
    """fetches the full details for this node from the main server."""
    print("info:     fetching node record from main server...")
    headers = {"x-node-secret-id": get_node_secret_id()}
    url = f"{MAIN_SERVER_URL}/nodes/me"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"error:    could not fetch node record: {e}")
        if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
            print("warn:     node not found in server database. node may need to be re-registered.")
        return None

async def main_startup_flow():
    """the main orchestration logic for node startup."""
    
    # 1. get this node's details from the server
    node_record = await get_self_node_record()
    if not node_record:
        print("critical: cannot start without node record. this should not happen after registration.")
        return

    hostname = node_record.get("public_hostname")
    port_range = node_record.get("port_range", [])
    
    if not all([hostname, port_range]):
        print("critical: node record is missing hostname or port_range. exiting.")
        return
        
    # we will use the first port in the assigned range for the main server
    main_server_port = port_range[0]

    # 2. determine public ip
    public_ip = await get_public_ip()
    if not public_ip:
        print("critical: could not determine public ip. exiting.")
        return

    # 3. request ssl certificate generation from server
    # the server handles dns updates, dns propagation checking, and ssl certificate generation
    print("info:     requesting ssl certificate generation from server...")
    cert_info = await request_ssl_certificate_from_server(public_ip)
    
    if not cert_info:
        print("critical: could not obtain ssl certificate from server. cannot start production server.")
        return

    cert_path = cert_info["cert_path"]
    key_path = cert_info["key_path"]

    # 4. final check for certificate files
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print(f"critical: ssl certificates not found at expected paths. aborting.")
        return

    print("info:     ssl certificate obtained successfully from server!")
    print("info:     node setup complete - ready to start production server!")

    # 5. start the production uvicorn server with the ssl certs
    print(f"info:     starting production server for {hostname} on port {main_server_port} with ssl...")
    
    uvicorn.run(
        "tunnel_node.main:app",
        host="0.0.0.0",
        port=main_server_port,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
        # use a reasonable number of worker processes
        workers=common_config.get("UVICORN_WORKERS", 2), 
    )

# --- phase 1: interactive registration logic ---

def get_node_secret_id():
    """gets or creates the node's permanent secret id."""
    try:
        with open(SECRET_ID_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        secret_id = str(uuid.uuid4())
        with open(SECRET_ID_FILE, "w") as f:
            f.write(secret_id)
        print(f"info:     generated new node secret id: {secret_id}")
        return secret_id

def run_reverse_benchmark():
    """
    performs a speed test by connecting *out* to the main server.
    this avoids firewall issues on the node.
    """
    print("info:     performing reverse benchmark...")
    try:
        # download test
        down_url = f"{MAIN_SERVER_URL}/registration/benchmark/download"
        start_time = time.monotonic()
        with requests.get(down_url, stream=True, timeout=20, verify=True) as r:
            r.raise_for_status()
            for _ in r.iter_content(chunk_size=8192): pass
        down_duration = time.monotonic() - start_time
        down_mbps = (BENCHMARK_PAYLOAD_SIZE / down_duration) * 8 / (1024*1024)
        print(f"info:     download speed: {down_mbps:.2f} mbps")

        # upload test
        up_url = f"{MAIN_SERVER_URL}/registration/benchmark/upload"
        dummy_payload = b'\0' * BENCHMARK_PAYLOAD_SIZE
        start_time = time.monotonic()
        r = requests.post(up_url, data=dummy_payload, timeout=20, verify=True)
        r.raise_for_status()
        up_duration = time.monotonic() - start_time
        up_mbps = (BENCHMARK_PAYLOAD_SIZE / up_duration) * 8 / (1024*1024)
        print(f"info:     upload speed: {up_mbps:.2f} mbps")

        return {"down_mbps": down_mbps, "up_mbps": up_mbps}
    except requests.RequestException as e:
        print(f"error:    benchmark failed: {e}")
        return None

async def run_interactive_registration(node_secret_id: str):
    """the main interactive registration coroutine."""
    # get public ip dynamically
    public_ip = await get_public_ip()
    if not public_ip:
        print("error:    could not determine public ip for registration")
        return False
        
    # for registration, we'll use a default port that gets updated later
    temp_public_address = f"http://{public_ip}:8201"
    print(f"info:     using temporary address for registration: {temp_public_address}")

    # before registering, we must send a heartbeat so the server knows our address
    print("info:     sending initial heartbeat...")
    try:
        heartbeat_response = requests.post(
            f"{MAIN_SERVER_URL}/nodes/register",
            json={"node_secret_id": node_secret_id, "public_address": temp_public_address},
            timeout=10, verify=True
        )
        print(f"info:     initial registration successful. {heartbeat_response.json().get('message', '')}")
        # give the database a moment to ensure the write is complete
        time.sleep(1)
    except requests.RequestException as e:
        sys.exit(f"error: could not send initial heartbeat to main server: {e}")

    ws_uri = MAIN_SERVER_URL.replace("http", "ws", 1) + "/registration/ws/register-node"
    print(f"--- tunnelite node registration ---")
    print(f"connecting to {ws_uri}...")

    try:
        # increase timeout for websocket connection and keepalive
        async with websockets.connect(ws_uri, ssl=True, open_timeout=30, close_timeout=10, ping_interval=60, ping_timeout=30) as websocket:
            print(f"authenticating with node secret id: {node_secret_id}")
            await websocket.send(json.dumps({
                "node_secret_id": node_secret_id,
                "admin_key": ADMIN_API_KEY,
            }))

            while True:
                try:
                    print("debug:    waiting for message from server...")
                    message_str = await asyncio.wait_for(websocket.recv(), timeout=300.0)  # 5 minutes for interactive prompts
                    print(f"debug:    received message: {message_str}")
                except asyncio.TimeoutError:
                    print("error:    timeout waiting for server message")
                    return False
                    
                try:
                    message = json.loads(message_str)
                    if not isinstance(message, dict):
                        print(f"warn:     received non-dict message from server: {message_str}")
                        continue
                except json.JSONDecodeError:
                    print(f"warn:     received malformed json from server: {message_str}")
                    continue

                msg_type = message.get("type")
                print(f"debug:    message type: {msg_type}")

                if msg_type == "reverse_benchmark":
                    benchmark_results = run_reverse_benchmark()
                    if not benchmark_results: return False
                    await websocket.send(json.dumps(benchmark_results))
                elif msg_type == "prompt":
                    response = input(f"[server] {message.get('message', '...')} > ")
                    await websocket.send(json.dumps({"response": response}))
                elif msg_type == "challenge":
                    print(f"[server] {message.get('message', 'responding to challenge...')}")
                    port, key = message.get('port'), message.get('key')
                    if not port or not key: return False
                    try:
                        challenge_url = f"http://{public_ip}:{port}/.well-known/acme-challenge/{key}"
                        # use a direct http request instead of a browser
                        response = requests.get(challenge_url, timeout=5)
                        response.raise_for_status()
                        print(f"info:     challenge endpoint is accessible: {challenge_url}")
                        await websocket.send(json.dumps({"status": "ready"}))
                    except Exception as e:
                        print(f"error:    challenge endpoint not accessible: {e}")
                        await websocket.send(json.dumps({"status": "failed", "error": str(e)}))
                elif msg_type == "info":
                    print(f"[server] {message.get('message', '...')}")
                elif msg_type == "success":
                    print(f"\n[server] success: {message.get('message', 'registration complete!')}")
                    # save node certificate if provided
                    if "node_cert" in message:
                        save_node_cert(message["node_cert"])
                    return True
                elif msg_type == "failure":
                    print(f"\n[server] failed: {message.get('message', 'registration failed.')}")
                    return False
    except Exception as e:
        print(f"an unexpected error occurred during registration: {e}")
        return False

def drop_privileges(uid_name: str, gid_name: str):
    """drops root privileges to a less privileged user and group."""
    if uid_name is None or gid_name is None:
        return
    
    import pwd
    import grp
    
    # get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # remove group privileges
    os.setgroups([])

    # try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # ensure a very conservative umask
    os.umask(0o077)

def start_worker_process(https_socket: socket.socket):
    print(f"info:     worker process started (pid: {os.getpid()})")
    drop_privileges(DROP_TO_USER, DROP_TO_GROUP)

    # disable background tasks in worker processes
    os.environ["ENABLE_BACKGROUND_TASKS"] = "false"

    # create a fresh, clean fastapi app for each worker to avoid middleware conflicts
    from fastapi import FastAPI
    from tunnel_node.main import websocket_endpoint, proxy_router
    
    worker_app = FastAPI(title="tunnelite-worker")
    worker_app.websocket("/ws/connect")(websocket_endpoint)
    worker_app.include_router(proxy_router)

    import uvicorn
    config = uvicorn.Config(
        app=worker_app,
        fd=https_socket.fileno(),
        log_level="info",
        lifespan="off",  # no startup/shutdown events needed for the isolated worker
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
    )
    server = uvicorn.Server(config)
    server.run()

def run_temp_api_server():
    """
    runs a temporary http server on port 8201 for acme challenges during registration.
    this is needed because certbot requires http-01 challenge validation.
    """
    print("info:     starting temporary api server on port 8201 for registration...")
    try:
        uvicorn.run(
            "tunnel_node.main:app",
            host="0.0.0.0",
            port=8201,
            log_level="warning",  # reduce noise during registration
            access_log=False
        )
    except Exception as e:
        print(f"error:    temporary api server failed: {e}")

def get_node_cert() -> str:
    """gets the stored node certificate"""
    try:
        with open(CERT_TOKEN_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def save_node_cert(cert: str):
    """saves the node certificate to disk"""
    with open(CERT_TOKEN_FILE, "w") as f:
        f.write(cert)
    print(f"info:     node certificate saved")

def get_node_port_range():
    """get the port range assigned to this node from the server"""
    node_record = requests.get(
        f"{MAIN_SERVER_URL}/nodes/me",
        headers={"x-node-secret-id": get_node_secret_id()},
        timeout=10
    ).json()
    
    port_range_str = node_record.get("port_range", "")
    if not port_range_str:
        print("error:    no port range assigned to this node")
        return []
    
    return parse_port_range(port_range_str)

def parse_port_range(range_str: str):
    """
    parses a port range string like "8000-8010,9000-9005" into a list of individual ports.
    """
    ports = []
    for part in range_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def find_available_port_in_range(port_list):
    """finds the first available port in the given list"""
    for port in port_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    return None

def run_background_service(updated_public_address: str):
    """
    runs the main background service that connects to the control channel.
    this replaces the old uvicorn server approach.
    """
    
    async def background_heartbeat():
        """sends periodic heartbeats to keep the node record fresh"""
        while True:
            try:
                await asyncio.sleep(60)  # heartbeat every minute
                node_info = {
                    "public_address": updated_public_address,
                    "cpu_usage": 0.0,  # placeholder
                    "memory_usage": 0.0,  # placeholder
                    "active_connections": 0  # placeholder
                }
                headers = {"x-node-cert": get_node_cert()}
                response = requests.post(
                    f"{MAIN_SERVER_URL}/nodes/heartbeat",
                    json=node_info,
                    headers=headers,
                    timeout=10
                )
                if response.status_code == 200:
                    print("debug:    heartbeat sent successfully")
                else:
                    print(f"warn:     heartbeat failed: {response.status_code}")
            except Exception as e:
                print(f"error:    heartbeat error: {e}")

    async def background_control_channel():
        """maintains connection to the server's control channel"""
        while True:
            try:
                node_secret_id = get_node_secret_id()
                ws_url = f"{MAIN_SERVER_URL.replace('https', 'wss')}/internal/control/ws?api_key={node_secret_id}"
                
                print(f"info:     connecting to control channel: {ws_url}")
                
                async with websockets.connect(ws_url, ssl=True) as websocket:
                    print("info:     connected to control channel")
                    
                    # send initial status
                    await websocket.send(json.dumps({
                        "type": "status_update",
                        "status": "online",
                        "public_address": updated_public_address
                    }))
                    
                    # listen for commands
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            msg_type = data.get("type")
                            
                            if msg_type == "activate_tunnel":
                                tunnel_id = data.get("tunnel_id")
                                print(f"info:     received tunnel activation: {tunnel_id}")
                                # todo: implement tunnel activation logic
                                await websocket.send(json.dumps({
                                    "type": "tunnel_status_update",
                                    "tunnel_id": tunnel_id,
                                    "status": "active"
                                }))
                            
                            elif msg_type == "deactivate_tunnel":
                                tunnel_id = data.get("tunnel_id")
                                print(f"info:     received tunnel deactivation: {tunnel_id}")
                                # todo: implement tunnel deactivation logic
                                await websocket.send(json.dumps({
                                    "type": "tunnel_status_update",
                                    "tunnel_id": tunnel_id,
                                    "status": "inactive"
                                }))
                                
                        except json.JSONDecodeError:
                            print(f"warn:     received invalid json from control channel: {message}")
                        except Exception as e:
                            print(f"error:    error processing control channel message: {e}")
                            
            except Exception as e:
                print(f"error:    control channel connection failed: {e}")
                print("info:     retrying in 30 seconds...")
                await asyncio.sleep(30)

    async def main():
        """run both background tasks concurrently"""
        await asyncio.gather(
            background_heartbeat(),
            background_control_channel()
        )

    # run the background service
    asyncio.run(main())

async def main():
    """main entry point."""
    if os.geteuid() != 0:
        print("error:    this script must be run as root to bind to low ports and manage ssl certificates.")
        # sys.exit(1) # commented for dev

    # check if we're already a registered node
    node_cert = get_node_cert()
    if node_cert:
        print("info:     node certificate found, verifying with server...")
        # verify the node still exists on the server
        node_record = await get_self_node_record()
        print(f"debug:    node_record result: {node_record}")
        if node_record:
            print("info:     node verified on server, running full production startup with ssl...")
            await main_startup_flow()
        else:
            print("warn:     node certificate exists but node not found on server. re-registering...")
            # clear the old cert and re-register
            if os.path.exists(CERT_TOKEN_FILE):
                os.remove(CERT_TOKEN_FILE)
            
            node_secret_id = get_node_secret_id()
            
            # run a temporary http server in the background to handle registration challenges
            temp_server_process = Process(target=run_temp_api_server, daemon=True)
            temp_server_process.start()
            await asyncio.sleep(2) # give it a moment to start up
            
            # run the registration flow
            registration_successful = await run_interactive_registration(node_secret_id)
            
            # stop the temp server
            print("info:     terminating temporary api server...")
            temp_server_process.terminate()
            temp_server_process.join(timeout=5)

            if not registration_successful:
                sys.exit("error:    registration failed.")
            else:
                print("info:     registration successful! proceeding to production startup.")
                await main_startup_flow()
    else:
        print("info:     node certificate not found, starting registration process...")
        node_secret_id = get_node_secret_id()
        
        # run a temporary http server in the background to handle registration challenges
        temp_server_process = Process(target=run_temp_api_server, daemon=True)
        temp_server_process.start()
        await asyncio.sleep(2) # give it a moment to start up
        
        # run the registration flow
        registration_successful = await run_interactive_registration(node_secret_id)
        
        # stop the temp server
        print("info:     terminating temporary api server...")
        temp_server_process.terminate()
        temp_server_process.join(timeout=5)

        if not registration_successful:
            sys.exit("error:    registration failed.")
        else:
            print("info:     registration successful! proceeding to production startup.")
            # after successful registration, we must proceed to the main startup flow
            # which handles ssl certificate generation and the final server launch.
            await main_startup_flow()

if __name__ == "__main__":
    asyncio.run(main())
