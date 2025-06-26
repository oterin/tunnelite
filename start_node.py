import asyncio
import json
import os
import sys
import pwd
import grp
import uuid
import time
from multiprocessing import Process, cpu_count
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import requests
import uvicorn
import websockets

# these imports are now relative to the project root
from tunnel_node.main import app as fastapi_app

# --- configuration ---
DROP_TO_USER = "tunnelite"
DROP_TO_GROUP = "tunnelite"
HTTPS_PORT = 443
CERT_FILE = "ssl/cert.pem"
KEY_FILE = "ssl/key.pem"
SECRET_ID_FILE = "node_secret_id.txt"

# main server url is configured via environment variable.
# it defaults to the standard, public-facing https port.
MAIN_SERVER_URL = os.getenv("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")
ADMIN_API_KEY = os.getenv("TUNNELITE_ADMIN_KEY")
NODE_PUBLIC_ADDRESS = os.getenv("NODE_PUBLIC_ADDRESS")


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

async def run_interactive_registration(node_secret_id: str):
    """the main interactive registration coroutine."""
    if not ADMIN_API_KEY:
        sys.exit("error: TUNNELITE_ADMIN_KEY not found in environment for registration.")
    if not NODE_PUBLIC_ADDRESS:
        sys.exit("error: NODE_PUBLIC_ADDRESS not found in environment for registration.")

    # before registering, we must send a heartbeat so the server knows our address
    print("info:     sending initial heartbeat...")
    try:
        requests.post(
            f"{MAIN_SERVER_URL}/nodes/register",
            json={"node_secret_id": node_secret_id, "public_address": NODE_PUBLIC_ADDRESS},
            timeout=10,
            verify=True # always verify ssl in production
        )
    except requests.RequestException as e:
        sys.exit(f"error: could not send initial heartbeat to main server: {e}")

    # construct the secure websocket uri
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

                if msg_type == "prompt":
                    response = input(f"[server] {message.get('message', '...')} > ")
                    await websocket.send(json.dumps({"response": response}))
                elif msg_type == "benchmark":
                    print(f"[server] {message.get('message', 'performing benchmark...')}")
                    await websocket.send(json.dumps({"type": "ready_for_benchmark"}))
                elif msg_type == "challenge":
                    print(f"[server] {message.get('message', 'responding to challenge...')}")
                    port, key = message.get('port'), message.get('key')
                    if not port or not key:
                        print("error:    received invalid challenge from server.")
                        return False
                    try:
                        node_api_url = NODE_PUBLIC_ADDRESS.replace("https", "http")
                        requests.post(
                            f"{node_api_url}/internal/setup-challenge-listener",
                            json={"port": port, "key": key},
                            timeout=3
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
                else:
                    print(f"warn:     received unknown message type '{msg_type}' from server.")
    except Exception as e:
        print(f"an unexpected error occurred during registration: {e}")
        return False


# --- phase 2: production server logic ---

def drop_privileges(uid_name: str, gid_name: str):
    """drops root privileges to a specified user and group for security."""
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
    """this is the main entrypoint for each worker process."""
    print(f"info:     worker process started (pid: {os.getpid()})")
    drop_privileges(DROP_TO_USER, DROP_TO_GROUP)

    # these must be imported *after* forking to prevent event loop conflicts.
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
    """runs a single, temporary uvicorn instance for registration challenges."""
    print("info:     starting temporary api server for registration...")
    try:
        # always bind to localhost for the temporary server
        host = "127.0.0.1"
        port = int(NODE_PUBLIC_ADDRESS.split(":")[-1])
        # we don't need the full startup logic for the temp server
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
            verify=True # always verify ssl
        )
        if res.status_code == 200 and res.json().get("status") == "approved":
            is_registered_and_approved = True
            print("info:     node is already registered and approved.")
        elif res.status_code == 404:
            print("info:     node is not yet registered.")
        else:
            print(f"warn:     received unexpected status from server: {res.status_code} {res.text}")
    except requests.RequestException as e:
        sys.exit(f"error: could not contact main server at {MAIN_SERVER_URL}. ({e})")

    if not is_registered_and_approved:
        temp_server_process = Process(target=run_temp_api_server)
        temp_server_process.start()
        print(f"info:     temporary api server started with pid: {temp_server_process.pid}")
        time.sleep(3) # give the server a moment to start up

        registration_success = asyncio.run(run_interactive_registration(node_secret_id))

        print("info:     terminating temporary api server...")
        temp_server_process.terminate()
        temp_server_process.join()

        if not registration_success:
            sys.exit("error: node registration failed. please check logs and try again.")
        print("info:     registration successful! proceeding to production startup.")

    # --- start the full production server ---
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
