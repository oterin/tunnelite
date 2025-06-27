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
    
    # color code based on event type
    if event_type == "connection":
        color = "green"
        icon = "●"
    elif event_type == "request":
        color = "cyan" 
        icon = "→"
    elif event_type == "response":
        status = event.get("metadata", {}).get("status_code", 200)
        if status < 300:
            color = "green"
        elif status < 400:
            color = "yellow"
        else:
            color = "red"
        icon = "←"
    elif event_type == "error":
        color = "red"
        icon = "✗"
    elif event_type == "tunnel":
        color = "blue"
        icon = "▲"
    else:
        color = "dim"
        icon = "•"
    
    return f"[dim]{timestamp}[/dim] [{color}]{icon}[/{color}] {message}"

# --- helper functions ---
async def ping_node(hostname: str) -> Optional[float]:
    """pings a node and returns latency in milliseconds, or None if unreachable"""
    try:
        # determine ping command based on platform
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "3", hostname]
        else:
            cmd = ["ping", "-c", "3", hostname]
        
        # run ping command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            # parse ping output to extract average latency
            output = result.stdout.lower()
            if platform.system().lower() == "windows":
                # windows format: "average = 123ms"
                if "average" in output:
                    avg_line = [line for line in output.split('\n') if 'average' in line]
                    if avg_line:
                        # extract number before "ms"
                        match = re.search(r'(\d+)ms', avg_line[0])
                        if match:
                            return float(match.group(1))
            else:
                # linux/mac format: "min/avg/max/stddev = 1.234/5.678/9.012/1.234 ms"
                if "min/avg/max" in output or "rtt min/avg/max" in output:
                    match = re.search(r'[\d.]+/([\d.]+)/[\d.]+', output)
                    if match:
                        return float(match.group(1))
        
        return None
    except Exception as e:
        console.print(f"[dim]ping failed for {hostname}: {e}[/dim]")
        return None

async def ping_all_nodes(api_key: str) -> Dict[str, float]:
    """pings all available nodes and returns latency data"""
    headers = {"x-api-key": api_key}
    
    try:
        # get available nodes
        res = requests.get(f"{main_server_url}/nodes/available", headers=headers)
        res.raise_for_status()
        nodes = res.json()
        
        if not nodes:
            console.print("[yellow]no nodes available for ping test[/yellow]")
            return {}
        
        console.print(f"[cyan]pinging {len(nodes)} nodes...[/cyan]")
        
        # ping all nodes concurrently
        ping_tasks = []
        for node in nodes:
            hostname = node["public_hostname"]
            # extract hostname from public_address if needed
            if "://" in node.get("public_address", ""):
                ping_host = node["public_address"].split("://")[1].split(":")[0]
            else:
                ping_host = hostname.split(".")[0] if "." in hostname else hostname
            
            ping_tasks.append((hostname, ping_node(ping_host)))
        
        # wait for all pings to complete
        ping_results = {}
        for hostname, ping_task in ping_tasks:
            latency = await ping_task
            if latency is not None:
                ping_results[hostname] = latency
                console.print(f"[green]✓[/green] {hostname}: {latency:.1f}ms")
            else:
                console.print(f"[red]✗[/red] {hostname}: unreachable")
        
        return ping_results
        
    except requests.RequestException as e:
        console.print(f"[red]failed to get node list: {e}[/red]")
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
    """displays the tunnelite header"""
    header = Text("TUNNELITE", style="bold cyan")
    subheader = Text("secure localhost tunneling", style="dim")
    panel = Panel.fit(f"{header}\n{subheader}", border_style="cyan")
    console.print(panel)
    console.print()

def show_user_info():
    """shows current user info if logged in"""
    api_key = get_api_key()
    if api_key:
        try:
            headers = {"x-api-key": api_key}
            res = requests.get(f"{main_server_url}/auth/users/me", headers=headers, timeout=5)
            if res.status_code == 200:
                username = res.json().get("username", "unknown")
                console.print(f"logged in as: [bold green]{username}[/bold green]")
            else:
                console.print("[yellow] invalid session - please login again[/yellow]")
        except requests.RequestException:
            console.print("[red] could not verify session[/red]")
    else:
        console.print("[dim]not logged in[/dim]")
    console.print()

def show_tunnel_status(tunnels: List[Dict]):
    """displays tunnels in a formatted table"""
    if not tunnels:
        console.print("[dim]no tunnels found[/dim]")
        return
    
    table = Table(title="Active Tunnels", box=box.ROUNDED)
    table.add_column("type", style="cyan")
    table.add_column("public url", style="blue")
    table.add_column("local port", style="green")
    table.add_column("status", style="bold")
    
    for tunnel in tunnels:
        status_style = "green" if tunnel["status"] == "active" else "yellow"
        table.add_row(
            tunnel["tunnel_type"],
            tunnel["public_url"],
            str(tunnel["local_port"]),
            f"[{status_style}]{tunnel['status']}[/{status_style}]"
        )
    
    console.print(table)

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
    """creates, activates, and runs a tunnel with live status display."""
    headers = {"x-api-key": api_key}
    start_time = time.time()
    request_count = 0
    bytes_in = 0
    bytes_out = 0
    request_log = []
    
    # tmux-like layout with multiple panes
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="main", ratio=1),
        Layout(name="footer", size=2)
    )
    
    layout["main"].split_row(
        Layout(name="status", ratio=1),
        Layout(name="logs", ratio=2)
    )

    def format_bytes(bytes_val):
        """format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f}TB"

    def make_layout(status: str, public_url: str = "", error: str = ""):
        # header - tmux style status bar
        uptime = time.time() - start_time if start_time else 0
        uptime_str = f"{int(uptime//3600):02d}:{int((uptime%3600)//60):02d}:{int(uptime%60):02d}"
        
        header_text = (
            f"[bold green]●[/bold green] tunnelite "
            f"[dim]│[/dim] {tunnel_type.upper()} "
            f"[dim]│[/dim] :{local_port} "
            f"[dim]│[/dim] {uptime_str} "
            f"[dim]│[/dim] {request_count} reqs "
            f"[dim]│[/dim] ↓{format_bytes(bytes_in)} ↑{format_bytes(bytes_out)}"
        )
        
        if error:
            header_text = f"[bold red]●[/bold red] error [dim]│[/dim] {error}"
        elif status != "active":
            header_text = f"[bold yellow]●[/bold yellow] {status}"
            
        layout["header"].update(Panel(header_text, border_style="bright_black"))
        
        # status pane
        if error:
            status_content = f"[red]✗ {error}[/red]"
        elif status == "pinging nodes":
            status_content = "[yellow]⟳ testing node latency...[/yellow]"
        elif status == "creating":
            status_content = "[yellow]⟳ creating tunnel...[/yellow]"
        elif status == "connecting":
            status_content = f"[yellow]⟳ connecting to node...[/yellow]\n[blue]{public_url}[/blue]"
        elif status == "active":
            status_content = (
                f"[green]✓ tunnel active[/green]\n\n"
                f"[bold]public url:[/bold]\n[blue]{public_url}[/blue]\n\n"
                f"[bold]forwarding:[/bold]\n{public_url} → localhost:{local_port}\n\n"
                f"[bold]stats:[/bold]\n"
                f"requests: [cyan]{request_count}[/cyan]\n"
                f"data in:  [green]{format_bytes(bytes_in)}[/green]\n"
                f"data out: [red]{format_bytes(bytes_out)}[/red]\n"
                f"uptime:   [yellow]{uptime_str}[/yellow]"
            )
        else:
            status_content = f"status: {status}"
            
        layout["status"].update(Panel(status_content, title="[bold]status[/bold]", border_style="bright_black"))
        
        # logs pane - combine network events and requests
        combined_log = []
        
        # add recent network events
        recent_network_events = network_events[-8:] if network_events else []
        for event in recent_network_events:
            combined_log.append(format_network_event(event))
        
        # add recent requests
        if request_log:
            combined_log.extend(request_log[-7:])
        
        log_content = "\n".join(combined_log) if combined_log else "[dim]waiting for activity...[/dim]"
        layout["logs"].update(Panel(log_content, title="[bold]network activity[/bold]", border_style="bright_black"))
        
        # footer
        footer_text = "[dim]press [bold]ctrl+c[/bold] to stop tunnel[/dim]"
        layout["footer"].update(Panel(footer_text, border_style="bright_black"))
        
        return layout

    def log_request(method: str, path: str, status_code: int, size: int, direction: str):
        """add request to log with tmux-style formatting"""
        timestamp = time.strftime("%H:%M:%S")
        
        # color code by status
        if status_code < 300:
            status_color = "green"
        elif status_code < 400:
            status_color = "yellow"
        else:
            status_color = "red"
            
        # direction arrow
        arrow = "→" if direction == "out" else "←"
        
        log_entry = f"[dim]{timestamp}[/dim] {arrow} [{status_color}]{status_code}[/{status_color}] {method} {path} [dim]({format_bytes(size)})[/dim]"
        request_log.append(log_entry)

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
    """interactive user registration"""
    clear_screen()
    show_header()
    
    console.print("[bold cyan]create new account[/bold cyan]")
    console.print()
    
    username = Prompt.ask("username")
    password = Prompt.ask("password", password=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("creating account...", total=None)
        
        try:
            res = requests.post(
                f"{main_server_url}/auth/register",
                json={"username": username, "password": password}
            )
            res.raise_for_status()
            progress.stop_task(task)
            console.print(" account created successfully!", style="green")
            console.print("you can now login with your credentials.")
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response else str(e)
            console.print(f" registration failed: {error_msg}", style="red")
    
    input("\npress enter to continue...")

def login_user():
    """interactive user login"""
    clear_screen()
    show_header()
    
    console.print("[bold cyan]login to tunnelite[/bold cyan]")
    console.print()
    
    username = Prompt.ask("username")
    password = Prompt.ask("password", password=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("logging in...", total=None)
        
        try:
            res = requests.post(
                f"{main_server_url}/auth/token",
                data={"username": username, "password": password}
            )
            res.raise_for_status()
            api_key = res.json()["api_key"]
            save_api_key(api_key)
            progress.stop_task(task)
            console.print(" login successful!", style="green")
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response else str(e)
            console.print(f" login failed: {error_msg}", style="red")
    
    input("\npress enter to continue...")

def view_tunnels():
    """view and manage active tunnels"""
    clear_screen()
    show_header()
    show_user_info()
    
    api_key = get_api_key()
    if not api_key:
        console.print("[red]not logged in[/red]")
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
        console.print(f"[red]error fetching tunnels: {error_msg}[/red]")
    
    input("\npress enter to continue...")

def create_tunnel():
    """interactive tunnel creation"""
    clear_screen()
    show_header()
    show_user_info()

    api_key = get_api_key()
    if not api_key:
        console.print("[red]not logged in - please login first[/red]")
        input("press enter to continue...")
        return
    
    console.print("[bold cyan]create new tunnel[/bold cyan]")
    console.print()
    
    tunnel_type = Prompt.ask(
        "tunnel type", 
        choices=["http", "tcp"], 
        default="http"
    )
    
    while True:
        try:
            local_port = int(Prompt.ask("local port"))
            if 1 <= local_port <= 65535:
                break
            console.print("[red]port must be between 1-65535[/red]")
        except ValueError:
            console.print("[red]please enter a valid port number[/red]")
    
    confirm = Confirm.ask(f"create {tunnel_type} tunnel for localhost:{local_port}?")
    
    if confirm:
        console.print("\nstarting tunnel...")
        try:
            asyncio.run(run_tunnel(api_key, tunnel_type, local_port))
        except KeyboardInterrupt:
            console.print("\n[yellow]tunnel stopped[/yellow]")
        input("press enter to continue...")

def show_main_menu():
    """displays the main tui menu"""
    while True:
        clear_screen()
        show_header()
        show_user_info()
        
        console.print("[bold]main menu[/bold]")
        console.print()
        console.print("1. create tunnel")
        console.print("2. view tunnels")
        console.print("3. login")
        console.print("4. register")
        console.print("5. logout")
        console.print("0. exit")
        console.print()
        
        choice = Prompt.ask("choose option", choices=["0", "1", "2", "3", "4", "5"])
        
        if choice == "0":
            console.print("goodbye! ")
            sys.exit(0)
        elif choice == "1":
            create_tunnel()
        elif choice == "2":
            view_tunnels()
        elif choice == "3":
            login_user()
        elif choice == "4":
            register_user()
        elif choice == "5":
            if os.path.exists(api_key_file):
                os.remove(api_key_file)
                console.print(" logged out successfully", style="green")
            else:
                console.print("not logged in", style="yellow")
            input("press enter to continue...")

# --- tui functions ---
def register_user():
    """interactive user registration"""
    clear_screen()
    show_header()
    
    console.print("[bold cyan]create new account[/bold cyan]")
    console.print()
    
    username = Prompt.ask("username")
    password = Prompt.ask("password", password=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("creating account...", total=None)
        
        try:
            res = requests.post(
                f"{main_server_url}/auth/register",
                json={"username": username, "password": password}
            )
            res.raise_for_status()
            progress.stop_task(task)
            console.print(" account created successfully!", style="green")
            console.print("you can now login with your credentials.")
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response else str(e)
            console.print(f" registration failed: {error_msg}", style="red")
    
    input("\npress enter to continue...")

# --- cli commands ---
@app.command()
def tui():
    """launch the full terminal user interface"""
    show_main_menu()

@app.command()
def quick(
    tunnel_type: str = typer.Argument("http", help="tunnel type (http, tcp)"),
    port: int = typer.Argument(..., help="local port to expose")
):
    """quickly create a tunnel without tui"""
    api_key = get_api_key()
    if not api_key:
        console.print("[red]not logged in - run 'tunnelite tui' first[/red]")
        raise typer.Exit(1)

    try:
        asyncio.run(run_tunnel(api_key, tunnel_type, port))
    except KeyboardInterrupt:
        console.print("\n[yellow]tunnel stopped[/yellow]")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """tunnelite - secure localhost tunneling"""
    if ctx.invoked_subcommand is None:
        show_main_menu()

if __name__ == "__main__":
    app()
