import asyncio
import json
import os
import websockets
import requests
from dotenv import load_dotenv

# load .env file from the current directory for the admin key
load_dotenv()

# --- configuration ---
MAIN_SERVER_URL = os.getenv("TUNNELITE_SERVER_URL", "http://127.0.0.1:8000")
ADMIN_API_KEY = os.getenv("TUNNELITE_ADMIN_KEY")
NODE_API_URL = os.getenv("NODE_PUBLIC_ADDRESS", "http://127.0.0.1:8001")
SECRET_ID_FILE = "node_secret_id.txt"

# convert http url to websocket url
WS_MAIN_SERVER_URL = MAIN_SERVER_URL.replace("http", "ws", 1)

async def run_registration():
    """the main interactive registration coroutine."""
    if not ADMIN_API_KEY:
        print("error: TUNNELITE_ADMIN_KEY not found in environment.")
        return

    try:
        with open(SECRET_ID_FILE, "r") as f:
            node_secret_id = f.read().strip()
    except FileNotFoundError:
        print(f"error: could not find {SECRET_ID_FILE}. please start the tunnel_node application once to generate it.")
        return

    uri = f"{WS_MAIN_SERVER_URL}/ws/register-node"
    print(f"--- tunnelite node registration ---")
    print(f"connecting to {uri}...")

    try:
        async with websockets.connect(uri) as websocket:
            # 1. initial handshake with admin key
            print(f"authenticating with node secret id: {node_secret_id}")
            await websocket.send(json.dumps({
                "node_secret_id": node_secret_id,
                "admin_key": ADMIN_API_KEY,
            }))

            # 2. handle interactive setup driven by the server
            while True:
                message_str = await websocket.recv()
                message = json.loads(message_str)
                msg_type = message.get("type")

                if msg_type == "prompt":
                    response = input(f"[server] {message['message']} > ")
                    await websocket.send(json.dumps({"response": response}))

                elif msg_type == "challenge":
                    print(f"[server] {message['message']}")
                    port = message['port']
                    key = message['key']

                    try:
                        requests.post(
                            f"{NODE_API_URL}/internal/setup-challenge-listener",
                            json={"port": port, "key": key}
                        )
                        print(f"[client] instructed node to listen on port {port}.")
                        await websocket.send(json.dumps({"type": "ready_for_challenge"}))
                    except requests.RequestException as e:
                        print(f"[client] error: could not contact local node api: {e}")
                        return

                elif msg_type == "info":
                    print(f"[server] {message['message']}")

                elif msg_type == "success":
                    print(f"\n[server] success: {message['message']}")
                    break

                elif msg_type == "failure":
                    print(f"\n[server] failed: {message['message']}")
                    break

    except websockets.exceptions.ConnectionClosed as e:
        print(f"connection closed by server: {e.reason} (code: {e.code})")
    except ConnectionRefusedError:
        print(f"error: connection refused. is the main server running at {MAIN_SERVER_URL}?")
    except Exception as e:
        print(f"an unexpected error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(run_registration())
