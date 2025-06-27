import asyncio
import getpass
import json
import os
import sys
import time
from typing import Optional, List, Dict

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
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=7),
        Layout(name="body", size=10),
        Layout(name="footer", size=3)
    )

    def make_layout(status: str, public_url: str = "", error: str = ""):
        # header
        header_panel = Panel(
            f"[bold cyan]TUNNELITE[/bold cyan] - {tunnel_type.upper()} tunnel\n"
            f"local port: [green]{local_port}[/green]",
            border_style="cyan"
        )
        layout["header"].update(header_panel)
        
        # body
        if error:
            body_panel = Panel(f"[red] {error}[/red]", border_style="red", title="error")
        elif status == "creating":
            body_panel = Panel("[yellow] creating tunnel...[/yellow]", border_style="yellow", title="status")
        elif status == "connecting":
            body_panel = Panel(
                f"[yellow] connecting to node...[/yellow]\n"
                f"public url: [blue]{public_url}[/blue]",
                border_style="yellow", title="status"
            )
        elif status == "active":
            uptime = time.time() - start_time
            uptime_str = f"{int(uptime//60)}m {int(uptime%60)}s"
            body_panel = Panel(
                f"[green] tunnel active![/green]\n"
                f"public url: [blue]{public_url}[/blue]\n"
                f"forwarding: localhost:{local_port}\n"
                f"uptime: {uptime_str} | requests: {request_count}",
                border_style="green", title="tunnel active"
            )
        else:
            body_panel = Panel(f"status: {status}", title="status")
            
        layout["body"].update(body_panel)
        
        # footer
        footer_panel = Panel("[dim]press ctrl+c to stop tunnel[/dim]", border_style="dim")
        layout["footer"].update(footer_panel)
        
        return layout

    with Live(make_layout("creating"), refresh_per_second=2) as live:
        try:
            # 1. create tunnel
        create_payload = {"tunnel_type": tunnel_type, "local_port": local_port}
        res = requests.post(f"{main_server_url}/tunnels", headers=headers, json=create_payload)
        res.raise_for_status()
        tunnel = res.json()

    tunnel_id = tunnel["tunnel_id"]
    public_url = tunnel["public_url"]
    public_hostname = tunnel["public_hostname"]

            # 2. get node details
            live.update(make_layout("connecting", public_url))
        node_res = requests.get(f"{main_server_url}/nodes/available", headers=headers)
        node_res.raise_for_status()
        target_node = next((n for n in node_res.json() if n["public_hostname"] == public_hostname), None)
            
        if not target_node:
                live.update(make_layout("", "", f"could not find assigned node '{public_hostname}'"))
                await asyncio.sleep(3)
                return

    node_ws_url = target_node["public_address"].replace("http", "ws", 1)
    connect_uri = f"{node_ws_url}/ws/connect"

            # 3. connect and run tunnel
        async with websockets.connect(connect_uri) as websocket:
            await websocket.send(json.dumps({"type": "activate", "tunnel_id": tunnel_id, "api_key": api_key}))

            activation_response_str = await websocket.recv()
            activation_response = json.loads(activation_response_str)
            if activation_response.get("status") != "success":
                    live.update(make_layout("", "", f"activation failed: {activation_response}"))
                    await asyncio.sleep(3)
                return

                live.update(make_layout("active", public_url))
                start_time = time.time()
                
                # proxy loop with live updates
            if tunnel_type in ["http", "https"]:
                while True:
                    request_from_node = await websocket.recv()
                    request_data_bytes = request_from_node if isinstance(request_from_node, bytes) else request_from_node.encode('utf-8')
                    response_to_node = await handle_http_request(local_port, request_data_bytes)
                    await websocket.send(response_to_node)
                        
                        request_count += 1
                        live.update(make_layout("active", public_url))
                        
            elif tunnel_type in ["tcp", "udp"]:
                await handle_tcp_stream(local_port, websocket)

        except requests.RequestException as e:
            error_msg = e.response.text if e.response else str(e)
            live.update(make_layout("", "", f"api error: {error_msg}"))
            await asyncio.sleep(3)
    except (ConnectionRefusedError, websockets.exceptions.InvalidURI):
            live.update(make_layout("", "", f"could not connect to node at {connect_uri}"))
            await asyncio.sleep(3)
    except websockets.exceptions.ConnectionClosed as e:
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
