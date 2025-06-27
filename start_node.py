import asyncio
import json
import os
import ssl
import sys
import pwd
import grp
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

# read the node public address from config
NODE_PUBLIC_ADDRESS = common_config.get("NODE_PUBLIC_ADDRESS")

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
HTTPS_PORT = 443                 # public https port to listen on
CERT_FILE = "ssl/cert.pem"       # tls cert for node
KEY_FILE = "ssl/key.pem"         # tls key for node
SECRET_ID_FILE = "node_secret_id.txt"  # local file storing node uuid
BENCHMARK_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 mb payload for bandwidth test

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
    if not NODE_PUBLIC_ADDRESS:
        sys.exit("error: NODE_PUBLIC_ADDRESS not configured in values.json for registration.")

    # before registering, we must send a heartbeat so the server knows our address
    print("info:     sending initial heartbeat...")
    try:
        requests.post(
            f"{MAIN_SERVER_URL}/nodes/register",
            json={"node_secret_id": node_secret_id, "public_address": NODE_PUBLIC_ADDRESS},
            timeout=10, verify=True
        )
    except requests.RequestException as e:
        sys.exit(f"error: could not send initial heartbeat to main server: {e}")

    ws_uri = MAIN_SERVER_URL.replace("http", "ws", 1) + "/ws/register-node"
    print(f"--- tunnelite node registration ---")
    print(f"connecting to {ws_uri}...")

    try:
        async with websockets.connect(ws_uri, ssl=True) as websocket:
            print(f"authenticating with node secret id: {node_secret_id}")
            await websocket.send(json.dumps({
                "node_secret_id": node_secret_id,
                "admin_key": ADMIN_API_KEY,
            }))

            while True:
                message_str = await websocket.recv()
                try:
                    message = json.loads(message_str)
                    if not isinstance(message, dict):
                        print(f"warn:     received non-dict message from server: {message_str}")
                        continue
                except json.JSONDecodeError:
                    print(f"warn:     received malformed json from server: {message_str}")
                    continue

                msg_type = message.get("type")

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
                        node_api_url = NODE_PUBLIC_ADDRESS.replace("https", "http")
                        requests.post(
                            f"{node_api_url}/internal/setup-challenge-listener",
                            json={"port": port, "key": key}, timeout=3
                        )
                        print(f"[client] instructed node to listen on port {port}.")
                        await websocket.send(json.dumps({"type": "ready_for_challenge"}))
                    except requests.RequestException as e:
                        print(f"[client] error: could not contact local api for challenge: {e}")
                        return False
                elif msg_type == "info":
                    print(f"[server] {message.get('message', '...')}")
                elif msg_type == "success":
                    print(f"\n[server] success: {message.get('message', 'registration complete!')}")
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

    from tunnel_node.main import on_startup as fastapi_startup
    import uvicorn

    fastapi_app.add_event_handler("startup", fastapi_startup)

    config = uvicorn.Config(
        app=fastapi_app,
        fd=https_socket.fileno(),
        log_level="info",
        lifespan="on",
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
    )
    server = uvicorn.Server(config)
    server.run()


def run_temp_api_server():
    print("info:     starting temporary api server for registration...")
    try:
        host = "127.0.0.1"
        port = int(NODE_PUBLIC_ADDRESS.split(":")[-1])
        from tunnel_node.main import app as temp_app
        uvicorn.run(temp_app, host=host, port=port, log_level="warning")
    except Exception as e:
        print(f"error: failed to start temporary server: {e}")

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

    try:
        https_socket = socket(AF_INET, SOCK_STREAM)
        https_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        https_socket.bind(('', HTTPS_PORT))
        https_socket.listen(128)
        print(f"info:     https socket bound to 0.0.0.0:{HTTPS_PORT} by main process (pid: {os.getpid()})")
    except Exception as e:
        sys.exit(f"error: failed to bind socket: {e}")

    num_workers = cpu_count()
    print(f"info:     spawning {num_workers} worker processes...")
    workers = []
    for _ in range(num_workers):
        worker = Process(target=start_worker_process, args=(https_socket,))
        workers.append(worker)
        worker.start()

    https_socket.close()

    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main process...")
        for worker in workers:
            worker.terminate()
            worker.join()

    print("info:     main process exited.")
