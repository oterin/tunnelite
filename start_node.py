import asyncio
import json
import os
import ssl
import sys
import uuid
import time
import socket
from multiprocessing import Process, cpu_count
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from urllib.parse import urlparse, urlunparse

import requests
import uvicorn
import websockets
import subprocess
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
    """Uses a third-party service to determine the node's public IP address."""
    try:
        print("info:     Fetching public IP address...")
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        response.raise_for_status()
        ip = response.json()["ip"]
        print(f"info:     Public IP address is {ip}")
        return ip
    except requests.RequestException as e:
        print(f"error:    Could not fetch public IP: {e}")
        return None

async def update_dns_record(ip: str):
    """Calls the main server's DDNS endpoint to update this node's A record."""
    print("info:     Notifying main server to update DNS record...")
    headers = {"x-api-key": get_node_secret_id()}
    payload = {"ip_address": ip}
    url = f"{MAIN_SERVER_URL}/internal/control/ddns-update"
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        print(f"info:     Successfully notified server of new IP: {ip}")
        return True
    except requests.RequestException as e:
        print(f"error:    Failed to update DNS record via server: {e}")
        if e.response:
            print(f"error details: {e.response.text}")
        return False

async def wait_for_dns_propagation(hostname: str, expected_ip: str):
    """
    Periodically checks DNS until the new IP address has propagated.
    This is crucial before attempting to get an SSL certificate.
    """
    print(f"info:     Waiting for DNS propagation for {hostname} to point to {expected_ip}...")
    # Wait up to 120 seconds (12 tries * 10s sleep)
    for i in range(12):
        try:
            # Note: This checks the DNS resolution from where the node is running.
            # This is a good indicator but not a guarantee of global propagation.
            resolved_ip = socket.gethostbyname(hostname)
            if resolved_ip == expected_ip:
                print("info:     DNS propagation successful!")
                return True
            else:
                print(f"debug:    DNS resolved to {resolved_ip}, waiting...")
        except socket.gaierror:
            print("debug:    DNS record not found yet, waiting...")
        
        await asyncio.sleep(10)
        
    print(f"error:    DNS for {hostname} did not propagate to {expected_ip} in time.")
    return False

def run_certbot(hostname: str, email: str):
    """
    Executes Certbot to obtain/renew an SSL certificate for the node's hostname.
    Assumes Certbot is installed on the system.
    """
    print("info:     Running Certbot to obtain SSL certificate...")
    # This command tells Certbot to get a certificate using the webroot plugin,
    # placing its challenge files where our FastAPI app can serve them.
    # The ACME_CHALLENGE_DIR must match the one in tunnel_node/main.py
    ACME_CHALLENGE_DIR = "/tmp/acme-challenges"
    command = [
        "certbot", "certonly",
        "--webroot", "-w", ACME_CHALLENGE_DIR,
        "-d", hostname,
        "--agree-tos",
        "-n",  # Non-interactive
        "-m", email,
        "--no-eff-email", # Don't ask to be on the EFF mailing list
        "--cert-name", hostname # Ensures we renew the correct cert
    ]
    try:
        # Using check=True will raise an exception if Certbot fails
        subprocess.run(command, check=True, capture_output=True, text=True)
        print("info:     Certbot run successful.")
        return True
    except FileNotFoundError:
        print("error:    'certbot' command not found. Please ensure it is installed and in the system's PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print("error:    Certbot failed.")
        print(f"Certbot stdout: {e.stdout}")
        print(f"Certbot stderr: {e.stderr}")
        return False

async def get_self_node_record():
    """Fetches the full details for this node from the main server."""
    print("info:     Fetching node record from main server...")
    headers = {"x-node-secret-id": get_node_secret_id()}
    url = f"{MAIN_SERVER_URL}/nodes/me"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"error:    Could not fetch node record: {e}")
        return None

async def main_startup_flow():
    """The main orchestration logic for node startup."""
    
    # 1. Get this node's details from the server
    node_record = await get_self_node_record()
    if not node_record:
        print("critical: Cannot start without node record. Exiting.")
        return

    hostname = node_record.get("public_hostname")
    # Assuming the server provides the owner's email for Certbot registration
    admin_email = node_record.get("owner_email", "admin@" + common_config.get("TUNNELITE_DOMAIN", "tunnelite.ws"))
    port_range = node_record.get("port_range", [])
    
    if not all([hostname, port_range]):
        print("critical: Node record is missing hostname or port_range. Exiting.")
        return
        
    # We will use the first port in the assigned range for the main server
    main_server_port = port_range[0]

    # 2. Determine public IP and update DNS via the server
    public_ip = await get_public_ip()
    if not public_ip:
        print("critical: Could not determine public IP. Exiting.")
        return
        
    if not await update_dns_record(public_ip):
        print("critical: Could not update DNS record. Exiting.")
        return

    # 3. Wait for the DNS change to propagate
    if not await wait_for_dns_propagation(hostname, public_ip):
        print("critical: DNS did not propagate. Tunnel will not be reachable. Exiting.")
        return

    # 4. Run Certbot to get/renew SSL certificates
    cert_path = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{hostname}/privkey.pem"

    # We can force a renewal check, or just run it if the cert doesn't exist.
    # Certbot is smart enough not to re-issue if the cert is still valid.
    if not run_certbot(hostname, admin_email):
        print("critical: Could not obtain SSL certificate. Cannot start production server.")
        return

    # 5. Final check for certificate files
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print(f"critical: SSL certificates not found at expected path after Certbot run. Aborting.")
        return

    # 6. Start the production Uvicorn server with the new SSL certs
    print(f"info:     Starting production server for {hostname} on port {main_server_port} with SSL...")
    
    uvicorn.run(
        "tunnel_node.main:app",
        host="0.0.0.0",
        port=main_server_port,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
        # Use a reasonable number of worker processes
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
    """
    this service runs in a separate process and handles two things:
    1. a periodic heartbeat to the main server.
    2. a persistent websocket control channel connection.
    """
    # this function will run in its own process, so it needs to import its own config
    from tunnel_node import config as t_config

    # also needs to init its own copy of the node cert
    node_cert = get_node_cert()
    node_secret_id = get_node_secret_id()

    async def background_heartbeat():
        """sends a heartbeat to the main server every 60 seconds."""
        while True:
            await asyncio.sleep(60)
            try:
                print(f"info:     ({time.ctime()}) sending heartbeat...")
                headers = {"x-api-key": node_secret_id}
                payload = {"public_address": updated_public_address, "node_cert": node_cert}
                response = requests.post(
                    f"{MAIN_SERVER_URL}/nodes/heartbeat",
                    headers=headers,
                    json=payload,
                    timeout=15,
                )
                response.raise_for_status()
                print("info:     heartbeat successful.")
            except requests.RequestException as e:
                print(f"error:    heartbeat failed: {e}")


    async def background_control_channel():
        """maintains the persistent control channel to the server."""
        ws_url = MAIN_SERVER_URL.replace("http", "ws")
        
        # NOTE: THIS IS THE WORKAROUND. The server expects an api_key.
        control_uri = f"{ws_url}/internal/control/ws?api_key={node_secret_id}"
        print(f"debug:    attempting to connect to: {control_uri}")
        
        attempts = 0
        max_attempts = 5
        base_wait_time = 10  # seconds

        while attempts < max_attempts:
            try:
                print(f"info:     connecting to control channel... (attempt {attempts + 1})")
                async with websockets.connect(control_uri) as websocket:
                    print("info:     background control channel connected.")
                    attempts = 0 # reset on successful connection

                    # main loop: listen for commands from server
                    async for message in websocket:
                        try:
                            command = json.loads(message)
                            print(f"info:     received command: {command}")
                            # command processing logic would go here
                        except json.JSONDecodeError:
                            print("error:    received malformed command from server.")
                        except Exception as e:
                            print(f"error:    error processing command: {e}")
                    
            except (websockets.exceptions.InvalidURI, websockets.exceptions.InvalidHandshake) as e:
                # these are usually permanent errors
                print(f"error:    background control channel failed: {e}. not retrying.")
                break
            except Exception as e:
                attempts += 1
                wait_time = base_wait_time * (2 ** (attempts - 1))
                print(f"warn:     background control channel failed: {e}. retrying in {wait_time}s... (attempt {attempts}/{max_attempts})")
                await asyncio.sleep(wait_time)

    async def main():
        print(f"info:     background service starting (pid: {os.getpid()}) with address {updated_public_address}")
        # run heartbeat and control channel concurrently
        await asyncio.gather(
            background_heartbeat(),
            background_control_channel()
        )

    # run the async main function
    asyncio.run(main())


async def main():
    """main entry point."""
    if os.geteuid() != 0:
        print("error:    this script must be run as root to bind to low ports and run certbot.")
        # sys.exit(1) # commented for dev

    # check if we're already a registered node
    node_cert = get_node_cert()
    if node_cert:
        print("info:     node certificate found, running full production startup with DNS and SSL...")
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
            # which handles DNS, certs, and the final server launch.
            await main_startup_flow()


if __name__ == "__main__":
    # configure python path to run this script from anywhere
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # global config setup - no initialization needed

    # set user/group for privilege drop if specified
    DROP_TO_USER = common_config.get("DROP_TO_USER")
    DROP_TO_GROUP = common_config.get("DROP_TO_GROUP")

    asyncio.run(main())
