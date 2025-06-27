import asyncio
import json
import os
import ssl
import sys
import uuid
import time
from multiprocessing import Process, cpu_count
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from urllib.parse import urlparse, urlunparse

import requests
import uvicorn
import websockets

# these imports are now relative to the project root
from tunnel_node.main import app as fastapi_app

# --- url configuration and normalization ---
# shared config helper
from server import config as common_config

# read the main server url from config
RAW_MAIN_SERVER_URL = common_config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

# admin key for registration
ADMIN_API_KEY = common_config.get("TUNNELITE_ADMIN_KEY")

def get_public_ip():
    """auto-detect public ip address"""
    try:
        # try multiple services for reliability
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me", 
            "https://icanhazip.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    return response.text.strip()
            except:
                continue
        
        # fallback: try to detect from local network interfaces
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
        
    except Exception as e:
        print(f"warn:     could not auto-detect public ip: {e}")
        return "127.0.0.1"  # fallback

# auto-detect public ip
PUBLIC_IP = get_public_ip()
print(f"info:     detected public ip: {PUBLIC_IP}")

# NODE_PUBLIC_ADDRESS will be set dynamically with actual port
NODE_PUBLIC_ADDRESS = None

def get_public_url(base_url: str) -> str:
    """
    parses a url and ensures it points to the standard public port (443 for https).
    this prevents errors when an internal port is accidentally included in the env var.
    """
    try:
        parsed = urlparse(base_url)
        # if scheme is https, we rebuild the url without a port, implying default port 443
        if parsed.scheme == "https":
            return urlunparse((parsed.scheme, parsed.hostname or '', parsed.path, '', '', ''))
        # for http (local dev), keep the port
        return base_url
    except Exception:
        # fallback to the raw url if parsing fails
        return base_url

MAIN_SERVER_URL = get_public_url(RAW_MAIN_SERVER_URL)

# --- static node configuration ---
DROP_TO_USER = "tunnelite"      # user to drop privs to
DROP_TO_GROUP = "tunnelite"     # group to drop privs to
CERT_FILE = "ssl/cert.pem"       # tls cert for node
KEY_FILE = "ssl/key.pem"         # tls key for node
SECRET_ID_FILE = "node_secret_id.txt"  # local file storing node uuid
BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 mb payload for bandwidth test
CERT_TOKEN_FILE = "node_cert.txt"     # jwt token for node auth

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
    # for registration, we'll use a default port that gets updated later
    temp_public_address = f"http://{PUBLIC_IP}:8201"
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
                        # connect to the local temporary api server, not the public address
                        local_port = int(temp_public_address.split(":")[-1])
                        local_api_url = f"http://127.0.0.1:{local_port}"
                        
                        # send the challenge setup request
                        response = requests.post(
                            f"{local_api_url}/internal/setup-challenge-listener",
                            json={"port": port, "key": key}, 
                            timeout=10  # longer timeout for setup
                        )
                        
                        if response.status_code == 200:
                            print(f"[client] challenge listener set up on port {port}.")
                            await websocket.send(json.dumps({"type": "ready_for_challenge"}))
                        else:
                            print(f"[client] error: challenge setup failed with status {response.status_code}: {response.text}")
                            return False
                            
                    except requests.RequestException as e:
                        print(f"[client] error: could not contact local api for challenge: {e}")
                        return False
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


# --- phase 2: production server logic ---

def drop_privileges(uid_name: str, gid_name: str):
    try:
        import pwd
        import grp
        new_uid = pwd.getpwnam(uid_name).pw_uid
        new_gid = grp.getgrnam(gid_name).gr_gid
    except KeyError:
        sys.exit(f"error: user '{uid_name}' or group '{gid_name}' not found. please create them first.")
    os.setgroups([])
    os.setgid(new_gid)
    os.setuid(new_uid)
    os.umask(0o077)
    print(f"info:     (pid: {os.getpid()}) process privileges dropped to {uid_name}:{gid_name}")

def start_worker_process(https_socket: socket):
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
    print("info:     starting temporary api server for registration...")
    try:
        host = "127.0.0.1"
        port = 8201  # use default port for temp server
        print(f"info:     temp server will bind to {host}:{port}")
        
        # check if port is available
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                print(f"info:     port {port} is available for temp server")
            except OSError as e:
                print(f"error:    port {port} is not available: {e}")
                return
        
        from tunnel_node.main import app as temp_app
        print(f"info:     starting uvicorn on {host}:{port}")
        uvicorn.run(temp_app, host=host, port=port, log_level="info")  # changed to info for better debugging
    except Exception as e:
        print(f"error: failed to start temporary server: {e}")
        import traceback
        print(f"traceback: {traceback.format_exc()}")

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
    """gets the node's registered port range from the server"""
    node_secret_id = get_node_secret_id()
    try:
        res = requests.get(
            f"{MAIN_SERVER_URL}/nodes/me",
            headers={"x-node-secret-id": node_secret_id},
            timeout=10, verify=True
        )
        if res.status_code == 200:
            node_data = res.json()
            print(f"debug:    received node data: {node_data}")
            port_range_str = node_data.get("port_range", "")
            print(f"debug:    port_range from server: '{port_range_str}'")
            parsed_ports = parse_port_range(port_range_str)
            print(f"debug:    parsed ports: {parsed_ports}")
            return parsed_ports
        else:
            print(f"warn:     could not get port range from server: {res.status_code} - {res.text}")
            return []
    except requests.RequestException as e:
        print(f"warn:     could not contact server for port range: {e}")
        return []

def parse_port_range(range_str: str):
    """parse port range string like '8202-8219' into list of ports"""
    ports = set()
    if not range_str:
        return []
    
    parts = [p.strip() for p in range_str.split(';')]
    for part in parts:
        if not part: 
            continue
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def find_available_port_in_range(port_list):
    """find the first available port from the list"""
    import socket
    for port in port_list:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    return None

def run_background_service(updated_public_address: str):
    """runs the background service (heartbeat and control channel) in a separate process"""
    print(f"info:     background service starting (pid: {os.getpid()}) with address {updated_public_address}")
    
    # import the background tasks from tunnel_node
    import asyncio
    import requests
    import time
    import json
    import websockets
    
    async def background_heartbeat():
        node_secret_id = get_node_secret_id()
        node_cert = get_node_cert()
        
        while True:
            await asyncio.sleep(60)  # heartbeat every minute
            
            # use the updated public address that reflects the actual running port
            node_details = {
                "node_secret_id": node_secret_id,
                "public_address": updated_public_address,  # use the passed parameter
                "metrics": {
                    "cpu_percent": 0,  # simplified for background service
                    "memory_percent": 0,
                    "active_connections": 0
                }
            }
            
            try:
                print(f"info:     ({time.ctime()}) sending heartbeat with address {updated_public_address}...")
                
                if node_cert:
                    try:
                        response = requests.post(
                            f"{MAIN_SERVER_URL}/nodes/heartbeat",
                            json=node_details,
                            headers={"x-node-cert": node_cert}
                        )
                    except requests.RequestException:
                        response = requests.post(
                            f"{MAIN_SERVER_URL}/nodes/register",
                            json=node_details
                        )
                else:
                    response = requests.post(
                        f"{MAIN_SERVER_URL}/nodes/register",
                        json=node_details
                    )
                    
                response.raise_for_status()
                print(f"info:     heartbeat successful, server updated with address {updated_public_address}")
                
            except requests.RequestException as e:
                print(f"error:    heartbeat failed: {e}")

    async def background_control_channel():
        retry_count = 0
        max_retries = 5
        
        await asyncio.sleep(10)  # wait for things to settle
        
        while True:
            try:
                node_cert = get_node_cert()
                ws_url = MAIN_SERVER_URL.replace("http", "ws", 1)
                
                if node_cert:
                    token_preview = node_cert[:20] + "..." if len(node_cert) > 20 else node_cert
                    control_uri = f"{ws_url}/ws/node-control-jwt?token={node_cert}"
                    print(f"info:     connecting to JWT control channel with token {token_preview} (attempt {retry_count + 1})")
                else:
                    control_uri = f"{ws_url}/ws/node-control"
                    print(f"info:     connecting to legacy control channel (attempt {retry_count + 1})")
                    
                async with websockets.connect(control_uri, ssl=True) as websocket:
                    if not node_cert:
                        auth_payload = {"type": "auth", "node_secret_id": get_node_secret_id()}
                        await websocket.send(json.dumps(auth_payload))
                        
                    print("info:     background control channel connected successfully.")
                    retry_count = 0

                    async for message in websocket:
                        try:
                            command = json.loads(message)
                            print(f"info:     received command: {command}")
                        except json.JSONDecodeError:
                            print("error:    received malformed command from server.")
                        except Exception as e:
                            print(f"error:    error processing command: {e}")

            except Exception as e:
                retry_count += 1
                if retry_count <= max_retries:
                    backoff_time = min(10 * retry_count, 60)
                    print(f"warn:     background control channel failed: {e}. retrying in {backoff_time}s... (attempt {retry_count}/{max_retries})")
                    await asyncio.sleep(backoff_time)
                else:
                    print(f"warn:     background control channel failed after {max_retries} attempts. giving up for 5 minutes.")
                    await asyncio.sleep(300)
                    retry_count = 0

    async def main():
        await asyncio.gather(
            background_heartbeat(),
            background_control_channel()
        )
    
    # run the background service
    asyncio.run(main())

# --- main entrypoint ---

if __name__ == "__main__":
    if sys.platform == "win32":
        sys.exit("error: this script is not supported on windows.")

    node_secret_id = get_node_secret_id()
    print(f"info:     node secret id: {node_secret_id}")

    print("info:     checking registration status with main server...")
    is_registered_and_approved = False
    try:
        res = requests.get(
            f"{MAIN_SERVER_URL}/nodes/me",
            headers={"x-node-secret-id": node_secret_id},
            timeout=10,
            verify=True
        )
        if res.status_code == 200:
            if res.json().get("status") == "approved":
                is_registered_and_approved = True
                print("info:     node is already registered and approved.")
            else:
                print(f"info:     node is registered but has status '{res.json().get('status')}'. starting registration...")
        elif res.status_code == 404:
            print("info:     node is not yet registered.")
        else:
            print(f"warn:     received unexpected status from server: {res.status_code} {res.text}")
    except requests.RequestException as e:
        sys.exit(f"error: could not contact main server at {MAIN_SERVER_URL}. ({e})")

    if not is_registered_and_approved:
        if not ADMIN_API_KEY:
            sys.exit("error: admin key missing in values.json")

        temp_server_process = Process(target=run_temp_api_server)
        temp_server_process.start()
        print(f"info:     temporary api server started with pid: {temp_server_process.pid}")
        time.sleep(3)

        # verify the temp server is responding
        temp_port = 8201  # use the same port as temp server
        temp_url = f"http://127.0.0.1:{temp_port}"
        for attempt in range(10):  # try for up to 10 seconds
            try:
                response = requests.get(f"{temp_url}/ping", timeout=2)
                if response.status_code == 200:
                    print(f"info:     temporary server is responding on {temp_url}")
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
            print(f"info:     waiting for temporary server... (attempt {attempt + 1}/10)")
        else:
            print("error:    temporary server is not responding after 10 seconds")
            temp_server_process.terminate()
            temp_server_process.join()
            sys.exit("error: could not start temporary api server")

        registration_success = asyncio.run(run_interactive_registration(node_secret_id))

        print("info:     terminating temporary api server...")
        temp_server_process.terminate()
        temp_server_process.join()

        if not registration_success:
            sys.exit("error: node registration failed. please check logs and try again.")
        print("info:     registration successful! proceeding to production startup.")

    if os.geteuid() != 0:
        sys.exit("error: must run as root to start production server and bind privileged ports.")

    print("info:     starting production server...")
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        sys.exit(f"error: ssl certificate '{CERT_FILE}' or key '{KEY_FILE}' not found.")

    # get available ports from the node's registered range
    available_ports = get_node_port_range()
    if not available_ports:
        sys.exit("error: could not get port range from server or no ports available")
    
    # find an available port in the range
    chosen_port = find_available_port_in_range(available_ports)
    if not chosen_port:
        sys.exit(f"error: no available ports in range {available_ports}")

    # set the public address to reflect the actual port we're running on
    # this ensures heartbeats and client connections use the correct port
    updated_public_address = f"https://{PUBLIC_IP}:{chosen_port}"
    
    print(f"info:     setting public address to {updated_public_address}")
    
    # update the global variable so heartbeats use the correct address
    NODE_PUBLIC_ADDRESS = updated_public_address
    
    # also update the tunnel_node config
    from tunnel_node import config as tunnel_config
    tunnel_config.set_node_public_address(chosen_port)
    
    # send an immediate heartbeat to update the server with the correct address
    print(f"info:     sending immediate heartbeat to update server with correct address...")
    try:
        node_cert = get_node_cert()
        immediate_heartbeat_data = {
            "node_secret_id": node_secret_id,
            "public_address": updated_public_address,
            "metrics": {
                "cpu_percent": 0,
                "memory_percent": 0,
                "active_connections": 0
            }
        }
        
        if node_cert:
            try:
                response = requests.post(
                    f"{MAIN_SERVER_URL}/nodes/heartbeat",
                    json=immediate_heartbeat_data,
                    headers={"x-node-cert": node_cert},
                    timeout=10
                )
            except requests.RequestException:
                response = requests.post(
                    f"{MAIN_SERVER_URL}/nodes/register",
                    json=immediate_heartbeat_data,
                    timeout=10
                )
        else:
            response = requests.post(
                f"{MAIN_SERVER_URL}/nodes/register",
                json=immediate_heartbeat_data,
                timeout=10
            )
        
        response.raise_for_status()
        print(f"info:     immediate heartbeat successful - server now has correct address {updated_public_address}")
        
    except requests.RequestException as e:
        print(f"warn:     immediate heartbeat failed: {e}, background service will retry")

    try:
        https_socket = socket(AF_INET, SOCK_STREAM)
        https_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        https_socket.bind(('', chosen_port))
        https_socket.listen(128)
        print(f"info:     https socket bound to 0.0.0.0:{chosen_port} by main process (pid: {os.getpid()})")
    except Exception as e:
        sys.exit(f"error: failed to bind socket on port {chosen_port}: {e}")

    # start background service in main process
    background_service_process = Process(target=run_background_service, args=(updated_public_address,))
    background_service_process.start()
    print(f"info:     background service started with pid: {background_service_process.pid}")

    # use only 1 worker process to avoid confusion
    max_workers = 1
    print(f"info:     spawning {max_workers} worker process...")
    workers = []
    for _ in range(max_workers):
        worker = Process(target=start_worker_process, args=(https_socket,))
        workers.append(worker)
        worker.start()

    https_socket.close()

    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main process...")
        background_service_process.terminate()
        background_service_process.join()
        for worker in workers:
            worker.terminate()
            worker.join()

    print("info:     main process exited.")
