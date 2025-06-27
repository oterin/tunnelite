import asyncio
import getpass
import json
import os
from typing import Optional

import requests
import typer
import websockets

# --- configuration ---
# we'll store the api key in the user's home directory for persistence.
home_dir = os.path.expanduser("~")
config_dir = os.path.join(home_dir, ".tunnelite")
api_key_file = os.path.join(config_dir, "api_key")

# you can override this with an environment variable for different environments.
main_server_url = os.getenv("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

# create the main cli application object.
app = typer.Typer(
    name="tunnelite",
    help="a simple and powerful localhost tunneling service.",
    add_completion=False,
)

# --- helper functions ---
def get_api_key() -> Optional[str]:
    """retrieves the api key from the local config file."""
    if not os.path.exists(api_key_file):
        return None
    with open(api_key_file, "r") as f:
        return f.read().strip()

def save_api_key(api_key: str):
    """saves the api key to the local config file."""
    os.makedirs(config_dir, exist_ok=True)
    with open(api_key_file, "w") as f:
        f.write(api_key)
    print("✅ api key saved successfully.")

# --- proxy logic (for http and tcp tunnels) ---
async def handle_http_request(local_port: int, request_data: bytes) -> bytes:
    """handles a single http request and returns the full response."""
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", local_port)
        writer.write(request_data)
        await writer.drain()

        response_data = await _.read(4096)
        writer.close()
        await writer.wait_closed()
        return response_data
    except ConnectionRefusedError:
        typer.secho(f"error: connection refused for localhost:{local_port}", fg=typer.colors.RED)
        return b"http/1.1 502 bad gateway\r\n\r\ntunnelite client could not connect to local service."
    except Exception as e:
        typer.secho(f"error: error forwarding to local service: {e}", fg=typer.colors.RED)
        return b"http/1.1 500 internal server error\r\n\r\ntunnelite client error."

async def handle_tcp_stream(local_port: int, websocket: websockets.WebSocketClientProtocol):
    """handles a bidirectional tcp stream."""
    local_writer = None
    try:
        local_reader, local_writer = await asyncio.open_connection("127.0.0.1", local_port)

        async def forward_to_local_task():
            """forwards data from websocket -> local tcp socket."""
            async for data in websocket:
                if isinstance(data, bytes):
                    local_writer.write(data)
                    await local_writer.drain()

        async def forward_to_ws_task():
            """forwards data from local tcp socket -> websocket."""
            while True:
                data = await local_reader.read(4096)
                if not data:
                    break # local connection closed
                await websocket.send(data)

        # run both forwarding tasks concurrently and cancel them if one finishes.
        # for example, if the local connection is closed, forward_to_ws_task will
        # break, and this gather will cancel forward_to_local_task.
        await asyncio.gather(forward_to_local_task(), forward_to_ws_task())

    except ConnectionRefusedError:
        typer.secho(f"error: connection refused for localhost:{local_port}", fg=typer.colors.RED)
    except (asyncio.CancelledError, websockets.exceptions.ConnectionClosed):
        pass # clean exit
    except Exception as e:
        typer.secho(f"error: an error occurred in the tcp stream: {e}", fg=typer.colors.RED)
    finally:
        if 'local_writer' in locals() and not local_writer.is_closing():
            local_writer.close()
            await local_writer.wait_closed()

# --- main tunnel coroutine ---
async def run_tunnel(api_key: str, tunnel_type: str, local_port: int):
    """creates, activates, and runs a tunnel."""
    headers = {"x-api-key": api_key}

    # 1. create the tunnel via the api
    typer.echo("creating tunnel...")
    try:
        create_payload = {"tunnel_type": tunnel_type, "local_port": local_port}
        res = requests.post(f"{main_server_url}/tunnels", headers=headers, json=create_payload)
        res.raise_for_status()
        tunnel = res.json()
    except requests.RequestException as e:
        typer.secho(f"error: could not create tunnel: {e.response.text if e.response else e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    tunnel_id = tunnel["tunnel_id"]
    public_url = tunnel["public_url"]
    public_hostname = tunnel["public_hostname"]

    # 2. get node connection details
    try:
        node_res = requests.get(f"{main_server_url}/nodes/available", headers=headers)
        node_res.raise_for_status()
        target_node = next((n for n in node_res.json() if n["public_hostname"] == public_hostname), None)
        if not target_node:
            typer.secho(f"error: could not find assigned node '{public_hostname}'", fg=typer.colors.RED)
            raise typer.Exit(code=1)
    except requests.RequestException as e:
        typer.secho(f"error: could not get node details: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    node_ws_url = target_node["public_address"].replace("http", "ws", 1)
    connect_uri = f"{node_ws_url}/ws/connect"

    # 3. connect to the node and run the tunnel
    # the client will now always attempt a secure wss:// connection.
    # the external load balancer is responsible for handling tls termination.
    try:
        async with websockets.connect(connect_uri) as websocket:
            # a. perform activation handshake
            await websocket.send(json.dumps({"type": "activate", "tunnel_id": tunnel_id, "api_key": api_key}))

            activation_response_str = await websocket.recv()
            activation_response = json.loads(activation_response_str)
            if activation_response.get("status") != "success":
                typer.secho(f"error: tunnel activation failed: {activation_response}", fg=typer.colors.RED)
                return

            typer.secho(f"tunnel activated!", fg=typer.colors.GREEN)
            typer.echo(f"  public url: {public_url}")
            typer.echo(f"  forwarding: localhost:{local_port}")
            typer.echo("...")

            # b. start the appropriate proxy loop
            if tunnel_type in ["http", "https"]:
                while True:
                    request_from_node = await websocket.recv()
                    request_data_bytes = request_from_node if isinstance(request_from_node, bytes) else request_from_node.encode('utf-8')
                    response_to_node = await handle_http_request(local_port, request_data_bytes)
                    await websocket.send(response_to_node)
            elif tunnel_type in ["tcp", "udp"]:
                await handle_tcp_stream(local_port, websocket)

    except (ConnectionRefusedError, websockets.exceptions.InvalidURI):
        typer.secho(f"error: could not connect to node at {connect_uri}", fg=typer.colors.RED)
    except websockets.exceptions.ConnectionClosed as e:
        typer.echo(f"connection to node closed: {e.reason} (code: {e.code})")

# --- cli commands ---
@app.command()
def login(
    username: str = typer.Argument(..., help="your username."),
):
    """log in to the tunnelite service and save your api key."""
    password = getpass.getpass("password: ")
    try:
        res = requests.post(
            f"{main_server_url}/auth/token",
            data={\"username\": username, \"password\": password}
        )
        res.raise_for_status()
        api_key = res.json()["api_key"]
        save_api_key(api_key)
    except requests.RequestException as e:
        typer.secho(f"error: login failed: {e.response.text if e.response else e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

@app.command(name="list")
def list_tunnels():
    """list your active and inactive tunnels."""
    api_key = get_api_key()
    if not api_key:
        typer.secho("you are not logged in. please run `tunnelite login <username>`.", fg=typer.colors.YELLOW)
        raise typer.Exit()

    headers = {"x-api-key": api_key}
    try:
        res = requests.get(f"{main_server_url}/tunnels", headers=headers)
        res.raise_for_status()
        tunnels = res.json()
        if not tunnels:
            typer.echo("you have no tunnels.")
            return

        typer.secho("your tunnels:", bold=True)
        for t in tunnels:
            status_color = typer.colors.GREEN if t['status'] == 'active' else typer.colors.BRIGHT_BLACK
            typer.secho(f"  - {t['public_url']} ({t['tunnel_type']}) -> localhost:{t['local_port']} [{t['status']}]", fg=status_color)

    except requests.RequestException as e:
        typer.secho(f"error: could not fetch tunnels: {e.response.text if e.response else e}", fg=typer.colors.RED)

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    tunnel_type: str = typer.Argument("http", help="the type of tunnel to create (http, tcp)."),
    port: int = typer.Argument(..., help="the local port to expose."),
):
    """
    creates a tunnel to a local port.
    e.g., `tunnelite http 8080` or `tunnelite tcp 5432`
    """
    if ctx.invoked_subcommand is not None:
        return # if a subcommand like 'login' was called, don't run this.

    api_key = get_api_key()
    if not api_key:
        typer.secho("you are not logged in. please run `tunnelite login <username>` first.", fg=typer.colors.YELLOW)
        raise typer.Exit()

    try:
        asyncio.run(run_tunnel(api_key, tunnel_type, port))
    except KeyboardInterrupt:
        typer.echo("\nshutting down tunnel.")

if __name__ == "__main__":
    app()
