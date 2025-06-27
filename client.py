import asyncio
import getpass
import json
import os
import re
import subprocess
import platform
import sys
import time
from typing import Optional, List, Dict
from urllib.parse import urlparse

import requests
import typer
import websockets
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.columns import Columns
from rich.align import Align

# --- configuration ---
# we'll store the api key in the user's home directory for persistence.
home_dir = os.path.expanduser("~")
config_dir = os.path.join(home_dir, ".tunnelite")
api_key_file = os.path.join(config_dir, "api_key")

# shared config loader
from server import config

# base url for api
main_server_url = config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

# create console for rich output
console = Console()

# create the main cli application object.
app = typer.Typer(
    name="tunnelite",
    help="a simple and powerful localhost tunneling service.",
    add_completion=False,
)

# add network logging functionality to the tui
network_events = []
max_network_events = 100

def add_network_event(event_type: str, message: str, metadata: dict = None):
    """add a network event to the local log"""
    global network_events
    timestamp = time.time()
    event = {
        "timestamp": timestamp,
        "type": event_type,
        "message": message,
        "metadata": metadata or {}
    }
    network_events.append(event)
    if len(network_events) > max_network_events:
        network_events.pop(0)

def format_network_event(event):
    """format a network event for display in the tui"""
    timestamp = time.strftime("%H:%M:%S", time.localtime(event["timestamp"]))
    event_type = event["type"]
    message = event["message"]
    
    # monochrome icons only
    if event_type == "connection":
        icon = "●"
    elif event_type == "request":
        icon = "→"
    elif event_type == "response":
        status = event.get("metadata", {}).get("status_code", 200)
        if status < 400:
            icon = "✓"
        else:
            icon = "✗"
    elif event_type == "error":
        icon = "✗"
    elif event_type == "tunnel":
        icon = "▲"
    else:
        icon = "•"
    
    return f"[dim]{timestamp}[/dim] {icon} {message}"

# --- helper functions ---
async def ping_node(hostname: str) -> Optional[float]:
    """ping a node and return latency in milliseconds"""
    try:
        system = platform.system().lower()
        if system == "windows":
            # windows ping command
            result = subprocess.run(
                ["ping", "-n", "1", hostname],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # parse windows ping output
                for line in result.stdout.split('\n'):
                    if 'time=' in line.lower():
                        time_part = line.split('time=')[1].split('ms')[0]
                        return float(time_part.replace('<', ''))
        else:
            # unix-like systems (linux, macos)
            result = subprocess.run(
                ["ping", "-c", "1", hostname],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # parse unix ping output
                for line in result.stdout.split('\n'):
                    if 'time=' in line:
                        time_part = line.split('time=')[1].split(' ')[0]
                        return float(time_part)
        return None
    except:
        return None

async def ping_all_nodes(api_key: str) -> Dict[str, float]:
    """ping all available nodes and return latency data"""
    headers = {"x-api-key": api_key}
    try:
        response = requests.get(f"{main_server_url}/nodes/available", headers=headers)
        response.raise_for_status()
        nodes = response.json()
        
        ping_tasks = []
        hostnames = []
        
        for node in nodes:
            hostname = node.get("public_hostname")
            if hostname:
                hostnames.append(hostname)
                ping_tasks.append(ping_node(hostname))
        
        if not ping_tasks:
            return {}
        
        # run all pings concurrently
        ping_results = await asyncio.gather(*ping_tasks)
        
        # build result dictionary
        ping_data = {}
        for hostname, latency in zip(hostnames, ping_results):
            if latency is not None:
                ping_data[hostname] = latency
        
        return ping_data
        
    except requests.RequestException:
        return {}

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
    console.print(" api key saved successfully.", style="green")

def clear_screen():
    """clears the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_header():
    """show centered monochrome header"""
    header_text = Text()
    header_text.append("tunnelite", style="bold")
    header_text.append(" / ", style="dim")
    header_text.append("localhost tunneling", style="dim")
    
    console.print()
    console.print(Align.center(header_text))
    console.print(Align.center("─" * 40, style="dim"))
    console.print()

def show_user_info():
    """show user authentication status"""
    api_key = get_api_key()
    if api_key:
        console.print(Align.center("[dim]authenticated[/dim]"))
    else:
        console.print(Align.center("[dim]not authenticated[/dim]"))
    console.print()

def show_tunnel_status(tunnels: List[Dict]):
    """show tunnel status in a centered table"""
    if not tunnels:
        console.print(Align.center("[dim]no active tunnels[/dim]"))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("type", style="dim")
    table.add_column("public url")
    table.add_column("local port", style="dim")
    table.add_column("status", justify="center")

    for tunnel in tunnels:
        status_icon = "●" if tunnel.get("status") == "active" else "○"
        table.add_row(
            tunnel.get("tunnel_type", "unknown"),
            tunnel.get("public_url", "unknown"),
            str(tunnel.get("local_port", "unknown")),
            status_icon
        )

    console.print(Align.center(table))

# --- proxy logic (for http and tcp tunnels) ---
async def handle_http_request(local_port: int, request_data: bytes) -> bytes:
    """forward http request to local server and return response"""
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', local_port)
        writer.write(request_data)
        await writer.drain()
        
        response_data = b""
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            response_data += chunk
        
        writer.close()
        await writer.wait_closed()
        return response_data
    except Exception as e:
        error_response = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(e))}\r\n\r\n{e}".encode()
        return error_response

async def handle_tcp_stream(local_port: int, websocket: websockets.WebSocketClientProtocol):
    """handle tcp tunnel streaming with proper bidirectional data flow"""
    try:
        # establish connection to local tcp service
        local_reader, local_writer = await asyncio.open_connection('127.0.0.1', local_port)
        print(f"debug:    connected to local tcp service on port {local_port}")
        
        async def forward_to_local_task():
            """forward data from websocket to local tcp service"""
            try:
                async for message in websocket:
                    if isinstance(message, bytes):
                        print(f"debug:    forwarding {len(message)} bytes from websocket to local service")
                        local_writer.write(message)
                        await local_writer.drain()
                    else:
                        print(f"debug:    received non-bytes message from websocket: {type(message)}")
            except websockets.exceptions.ConnectionClosed:
                print("debug:    websocket connection closed in forward_to_local_task")
            except Exception as e:
                print(f"debug:    error in forward_to_local_task: {e}")
            finally:
                if not local_writer.is_closing():
                    local_writer.close()
                    try:
                        await local_writer.wait_closed()
                    except:
                        pass

        async def forward_to_ws_task():
            """forward data from local tcp service to websocket"""
            try:
                while True:
                    data = await local_reader.read(4096)
                    if not data:
                        print("debug:    local tcp connection closed")
                        break
                    print(f"debug:    forwarding {len(data)} bytes from local service to websocket")
                    await websocket.send(data)
            except websockets.exceptions.ConnectionClosed:
                print("debug:    websocket connection closed in forward_to_ws_task")
            except Exception as e:
                print(f"debug:    error in forward_to_ws_task: {e}")

        # run both forwarding tasks concurrently
        await asyncio.gather(
            forward_to_local_task(),
            forward_to_ws_task(),
            return_exceptions=True
        )
        
    except ConnectionRefusedError:
        print(f"error:    could not connect to local service on port {local_port}")
        add_network_event("error", f"local service on port {local_port} refused connection")
    except Exception as e:
        print(f"error:    tcp stream error: {e}")
        add_network_event("error", f"tcp stream error: {e}")

# --- main tunnel coroutine ---
async def run_tunnel(api_key: str, tunnel_type: str, local_port: int):
    """run tunnel with beautiful centered tui"""
    headers = {"x-api-key": api_key}
    
    # state variables
    request_count = 0
    bytes_in = 0
    bytes_out = 0
    start_time = None
    request_log = []
    
    def format_bytes(bytes_val):
        """format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f}TB"

    def make_layout(status: str, public_url: str = "", error: str = ""):
        """create beautiful centered layout"""
        layout = Layout()
        
        # main container with padding
        layout.split_column(
            Layout(name="header", size=7),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # header section
        if error:
            header_content = Panel(
                Align.center(f"[bold]● error[/bold]\n[dim]{error}[/dim]"),
                box=box.SIMPLE,
                style="dim"
            )
        elif status == "active":
            uptime = time.time() - start_time if start_time else 0
            uptime_str = f"{int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}"
            
            stats_text = (
                f"[bold]tunnelite[/bold] [dim]│[/dim] "
                f"{tunnel_type.upper()} [dim]│[/dim] "
                f":{local_port} [dim]│[/dim] "
                f"{uptime_str} [dim]│[/dim] "
                f"{request_count} reqs [dim]│[/dim] "
                f"↓{format_bytes(bytes_in)} ↑{format_bytes(bytes_out)}"
            )
            
            header_content = Panel(
                Align.center(stats_text),
                box=box.SIMPLE,
                style="bold"
            )
        else:
            status_text = {
                "creating": "creating tunnel",
                "pinging nodes": "testing node latency",
                "connecting": "connecting to node"
            }.get(status, status)
            
            header_content = Panel(
                Align.center(f"[bold]● {status_text}[/bold]"),
                box=box.SIMPLE,
                style="dim"
            )
        
        layout["header"].update(header_content)
         
        # main content area - just center and right columns
        layout["main"].split_row(
            Layout(name="center", ratio=3),
            Layout(name="right", ratio=2)
        )
        
        # center column with tunnel info
        if status == "active" and public_url:
            tunnel_info = Panel(
                Align.center(
                    f"[bold]tunnel active[/bold]\n\n"
                    f"[dim]public url:[/dim]\n{public_url}\n\n"
                    f"[dim]forwarding:[/dim]\n{public_url} → localhost:{local_port}\n\n"
                    f"[dim]requests:[/dim] {request_count}\n"
                    f"[dim]data in:[/dim] {format_bytes(bytes_in)}\n"
                    f"[dim]data out:[/dim] {format_bytes(bytes_out)}"
                ),
                title="status",
                box=box.SIMPLE
            )
        elif error:
            tunnel_info = Panel(
                Align.center(f"[dim]{error}[/dim]"),
                title="error",
                box=box.SIMPLE
            )
        elif public_url:
            tunnel_info = Panel(
                Align.center(f"[dim]connecting to[/dim]\n{public_url}"),
                title="status",
                box=box.SIMPLE
            )
        else:
            tunnel_info = Panel(
                Align.center(f"[dim]{status}...[/dim]"),
                title="status",
                box=box.SIMPLE
            )
        
        layout["center"].update(tunnel_info)
        
        # activity log in right column (smaller)
        combined_log = []
        
        # add recent network events
        recent_network_events = network_events[-6:] if network_events else []
        for event in recent_network_events:
            combined_log.append(format_network_event(event))
        
        # add recent requests
        if request_log:
            combined_log.extend(request_log[-4:])
        
        if not combined_log:
            log_content = "[dim]waiting for activity...[/dim]"
        else:
            log_content = "\n".join(combined_log)
        
        activity_panel = Panel(
            log_content,
            title="activity",
            box=box.SIMPLE,
            style="dim"
        )
        layout["right"].update(activity_panel)
        
        # footer
        footer_content = Panel(
            Align.center("[dim]press [bold]ctrl+c[/bold] to stop[/dim]"),
            box=box.SIMPLE,
            style="dim"
        )
        layout["footer"].update(footer_content)
        
        return layout

    def log_request(method: str, path: str, status_code: int, size: int, direction: str):
        """add request to log"""
        timestamp = time.strftime("%H:%M:%S")
        
        # simple monochrome formatting
        status_icon = "✓" if status_code < 400 else "✗"
        arrow = "→" if direction == "out" else "←"
        
        log_entry = f"[dim]{timestamp}[/dim] {arrow} {status_icon} {method} {path}"
        request_log.append(log_entry)
        
        # keep log size manageable
        if len(request_log) > 20:
            request_log.pop(0)

    with Live(make_layout("creating"), refresh_per_second=4) as live:
        try:
            # 1. ping all nodes to get latency data
            live.update(make_layout("pinging nodes"))
            add_network_event("tunnel", "pinging nodes for optimal selection")
            ping_data = await ping_all_nodes(api_key)
            
            # 2. create tunnel with ping data
            live.update(make_layout("creating"))
            add_network_event("tunnel", f"creating {tunnel_type} tunnel on port {local_port}")
            create_payload = {
                "tunnel_type": tunnel_type, 
                "local_port": local_port,
                "ping_data": ping_data
            }
            res = requests.post(f"{main_server_url}/tunnels", headers=headers, json=create_payload)
            res.raise_for_status()
            tunnel = res.json()
            add_network_event("tunnel", f"tunnel created: {tunnel['public_url']}")

            tunnel_id = tunnel["tunnel_id"]
            public_url = tunnel["public_url"]
            public_hostname = tunnel["public_hostname"]

            # 3. get node details for the server-selected node
            live.update(make_layout("connecting", public_url))
            node_res = requests.get(f"{main_server_url}/nodes/available", headers=headers)
            node_res.raise_for_status()
            target_node = next((n for n in node_res.json() if n["public_hostname"] == public_hostname), None)
            
            if not target_node:
                live.update(make_layout("", "", f"could not find assigned node '{public_hostname}'"))
                await asyncio.sleep(3)
                return
            
            # use the hostname for the connection, not the ip, for proper ssl verification.
            hostname_for_ws = target_node["public_hostname"]
            port_for_ws = urlparse(target_node["public_address"]).port
            
            node_ws_url = f"wss://{hostname_for_ws}:{port_for_ws}"
            connect_uri = f"{node_ws_url}/ws/connect"

            # 4. connect and run tunnel
            add_network_event("connection", f"connecting to {hostname_for_ws}")
            async with websockets.connect(connect_uri) as websocket:
                add_network_event("connection", "websocket connected")
                await websocket.send(json.dumps({"type": "activate", "tunnel_id": tunnel_id, "api_key": api_key}))

                activation_response_str = await websocket.recv()
                activation_response = json.loads(activation_response_str)
                if activation_response.get("status") != "success":
                    add_network_event("error", f"activation failed: {activation_response}")
                    live.update(make_layout("", "", f"activation failed: {activation_response}"))
                    await asyncio.sleep(3)
                    return

                add_network_event("tunnel", "tunnel activated successfully")
                live.update(make_layout("active", public_url))
                start_time = time.time()
                
                # proxy loop with live updates and request logging
                if tunnel_type in ["http", "https"]:
                    while True:
                        request_from_node = await websocket.recv()
                        request_data_bytes = request_from_node if isinstance(request_from_node, bytes) else request_from_node.encode('utf-8')
                        
                        # parse request for logging
                        try:
                            request_str = request_data_bytes.decode('utf-8')
                            lines = request_str.split('\n')
                            if lines:
                                method, path = lines[0].split()[:2]
                        except:
                            method, path = "?", "/"
                        
                        # log incoming request
                        add_network_event("request", f"{method} {path}", {"method": method, "path": path})
                        
                        response_to_node = await handle_http_request(local_port, request_data_bytes)
                        
                        # parse response status for logging
                        try:
                            response_str = response_to_node.decode('utf-8')
                            status_line = response_str.split('\n')[0]
                            status_code = int(status_line.split()[1])
                        except:
                            status_code = 200
                        
                        # log outgoing response
                        add_network_event("response", f"HTTP {status_code}", {"status_code": status_code})
                        
                        await websocket.send(response_to_node)
                        
                        # update stats and log
                        request_count += 1
                        bytes_in += len(request_data_bytes)
                        bytes_out += len(response_to_node)
                        
                        log_request(method, path, status_code, len(response_to_node), "out")
                        live.update(make_layout("active", public_url))
                        
                elif tunnel_type in ["tcp", "udp"]:
                    add_network_event("tunnel", f"starting {tunnel_type} tunnel on port {local_port}")
                    print(f"debug:    starting tcp tunnel, forwarding {public_url} -> localhost:{local_port}")
                    await handle_tcp_stream(local_port, websocket)

        except requests.RequestException as e:
            error_msg = e.response.text if e.response else str(e)
            add_network_event("error", f"api error: {error_msg}")
            live.update(make_layout("", "", f"api error: {error_msg}"))
            await asyncio.sleep(3)
        except (ConnectionRefusedError, websockets.exceptions.InvalidURI):
            add_network_event("error", f"could not connect to node at {connect_uri}")
            live.update(make_layout("", "", f"could not connect to node at {connect_uri}"))
            await asyncio.sleep(3)
        except websockets.exceptions.ConnectionClosed as e:
            add_network_event("connection", f"connection closed: {e.reason} (code: {e.code})")
            live.update(make_layout("", "", f"connection closed: {e.reason} (code: {e.code})"))
            await asyncio.sleep(3)

# --- tui functions ---
def register_user():
    """interactive user registration with centered layout"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]create new account[/bold]"))
    console.print()
    
    # centered input prompts
    username = Prompt.ask("  username", console=console)
    password = Prompt.ask("  password", password=True, console=console)
    
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("  creating account...", total=None)
        
        try:
            res = requests.post(
                f"{main_server_url}/auth/register",
                json={"username": username, "password": password}
            )
            res.raise_for_status()
            progress.stop_task(task)
            console.print(Align.center("✓ account created successfully"))
            console.print(Align.center("[dim]you can now login with your credentials[/dim]"))
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response else str(e)
            console.print(Align.center(f"✗ registration failed: {error_msg}"))
    
    console.print()
    input(Align.center("press enter to continue...").plain)

def login_user():
    """interactive user login with centered layout"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]login to tunnelite[/bold]"))
    console.print()
    
    username = Prompt.ask("  username", console=console)
    password = Prompt.ask("  password", password=True, console=console)
    
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("  logging in...", total=None)
        
        try:
            res = requests.post(
                f"{main_server_url}/auth/token",
                data={"username": username, "password": password}
            )
            res.raise_for_status()
            api_key = res.json()["api_key"]
            save_api_key(api_key)
            progress.stop_task(task)
            console.print(Align.center("✓ login successful"))
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response else str(e)
            console.print(Align.center(f"✗ login failed: {error_msg}"))
    
    console.print()
    input("press enter to continue...")

def view_tunnels():
    """view and manage active tunnels with centered layout"""
    clear_screen()
    show_header()
    show_user_info()
    
    api_key = get_api_key()
    if not api_key:
        console.print(Align.center("[dim]not logged in[/dim]"))
        input("press enter to continue...")
        return

    headers = {"x-api-key": api_key}
    try:
        res = requests.get(f"{main_server_url}/tunnels", headers=headers)
        res.raise_for_status()
        tunnels = res.json()
        show_tunnel_status(tunnels)

    except requests.RequestException as e:
        error_msg = e.response.text if e.response else str(e)
        console.print(Align.center(f"[dim]error fetching tunnels: {error_msg}[/dim]"))
    
    console.print()
    input("press enter to continue...")

def create_tunnel():
    """interactive tunnel creation with centered layout"""
    clear_screen()
    show_header()
    show_user_info()

    api_key = get_api_key()
    if not api_key:
        console.print(Align.center("[dim]not logged in - please login first[/dim]"))
        input("press enter to continue...")
        return
    
    console.print(Align.center("[bold]create new tunnel[/bold]"))
    console.print()
    
    # tunnel type selection
    tunnel_type = Prompt.ask(
        "  tunnel type",
        choices=["http", "tcp"],
        default="http",
        console=console
    )
    
    # local port input
    while True:
        try:
            local_port = int(Prompt.ask("  local port", console=console))
            if 1 <= local_port <= 65535:
                break
            else:
                console.print(Align.center("[dim]port must be between 1 and 65535[/dim]"))
        except ValueError:
            console.print(Align.center("[dim]please enter a valid port number[/dim]"))
    
    console.print()
    
    # run the tunnel
    try:
        asyncio.run(run_tunnel(api_key, tunnel_type, local_port))
    except KeyboardInterrupt:
        console.print()
        console.print(Align.center("[dim]tunnel stopped[/dim]"))
        console.print()

def show_main_menu():
    """show main menu with centered layout"""
    clear_screen()
    show_header()
    show_user_info()
    
    # create centered menu
    menu_items = [
        "1. create tunnel",
        "2. view tunnels", 
        "3. login",
        "4. register",
        "5. exit"
    ]
    
    console.print(Align.center("[bold]main menu[/bold]"))
    console.print()
    
    for item in menu_items:
        console.print(Align.center(f"[dim]{item}[/dim]"))
    
    console.print()
    
    choice = Prompt.ask("  choose option", choices=["1", "2", "3", "4", "5"], console=console)
    
    if choice == "1":
        create_tunnel()
    elif choice == "2":
        view_tunnels()
    elif choice == "3":
        login_user()
    elif choice == "4":
        register_user()
    elif choice == "5":
        console.print()
        console.print(Align.center("[dim]goodbye[/dim]"))
        sys.exit(0)

@app.command()
def tui():
    """start the interactive tui"""
    try:
        while True:
            show_main_menu()
    except KeyboardInterrupt:
        console.print()
        console.print(Align.center("[dim]goodbye[/dim]"))

@app.command()
def quick(
    tunnel_type: str = typer.Argument("http", help="tunnel type (http, tcp)"),
    port: int = typer.Argument(..., help="local port to expose")
):
    """quickly create a tunnel without the tui"""
    api_key = get_api_key()
    if not api_key:
        console.print("error: not logged in. run 'python client.py tui' to login first.")
        return
    
    try:
        asyncio.run(run_tunnel(api_key, tunnel_type, port))
    except KeyboardInterrupt:
        console.print("\ntunnel stopped.")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """tunnelite client - localhost tunneling made simple"""
    if ctx.invoked_subcommand is None:
        tui()

if __name__ == "__main__":
    app()
