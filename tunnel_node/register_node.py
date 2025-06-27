import asyncio
import json
import websockets
import requests

# shared config loader
from server import config

MAIN_SERVER_URL = config.get("TUNNELITE_SERVER_URL", "http://127.0.0.1:8000")
NODE_API_URL = config.get("NODE_PUBLIC_ADDRESS", "http://127.0.0.1:8001")

WS_MAIN_SERVER_URL = MAIN_SERVER_URL.replace("http://", "ws://").replace("https://", "wss://")

SECRET_ID_FILE = "node_secret_id.txt"
NODE_SECRET_ID = None
try:
    with open(SECRET_ID_FILE, "r") as f:
        NODE_SECRET_ID = f.read().strip()
except FileNotFoundError:
    pass

async def run_registration():
    uri = f"{WS_MAIN_SERVER_URL}/ws/register-node"
    print(f"--- tunnelite node registration ---")
    print(f"connecting to {uri}...")

    async with websockets.connect(uri) as websocket:
        print(f"identifying with node secret id: {NODE_SECRET_ID}")
        await websocket.send(json.dumps({"node_secret_id": NODE_SECRET_ID}))

        while True:
            try:
                message = await websocket.recv()
                data = json.loads(message)
                msg_type = data.get("type")

                if msg_type == "benchmark":
                    print("server: initiating bandwidth benchmark...")
                    await websocket.send(json.dumps({"type": "ready_for_benchmark"}))

                elif msg_type == "info":
                    print(f"server: {data['message']}")

                elif msg_type == "prompt":
                    response = input(f"server: {data['message']} > ")
                    await websocket.send(json.dumps({"response": response}))

                elif msg_type == "challenge":
                    print(f"server: {data['message']}")
                    port, key = data['port'], data['key']
                    try:
                        requests.post(
                            f"{NODE_API_URL}/internal/setup-challenge-listener",
                            json={"port": port, "key": key}
                        )
                        print(f"client: told node to listen on port {port}.")
                        await websocket.send(json.dumps({"type": "ready_for_challenge"}))
                    except requests.RequestException as e:
                        print(f"client error: couldn't reach local node api: {e}")
                        return

                elif msg_type == "success":
                    print(f"\nserver: success: {data['message']}")
                    break

                elif msg_type == "failure":
                    print(f"\nserver: failed: {data['message']}")
                    break

            except websockets.ConnectionClosed as e:
                print(f"connection closed: {e.reason} (code: {e.code})")
                break

if __name__ == "__main__":
    if not NODE_SECRET_ID:
        print(f"error: couldn't find {SECRET_ID_FILE}. please start the tunnel_node application once to generate it.")
    else:
        asyncio.run(run_registration())
