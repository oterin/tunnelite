import asyncio
import getpass
import json
import os
import re
import subprocess
import platform
import sys
import time
from typing import Optional, List, Dict, Tuple
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

import certifi

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
        response = requests.get(f"{main_server_url}/nodes/available", headers=headers, verify=certifi.where())
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

# --- main tunnel coroutine ---
async def run_tunnel(api_key: str, tunnel_type: str, local_port: int):
    """the main coroutine that establishes and maintains a tunnel connection."""
    
    sub_connections = {} # tracks tcp sub-connections for a single tcp tunnel
    
    def format_bytes(bytes_val):
        if bytes_val < 1024:
            return f"{bytes_val} b"
        elif bytes_val < 1024**2:
            return f"{bytes_val/1024:.1f} kb"
        else:
            return f"{bytes_val/1024**2:.1f} mb"

    def make_layout(status: str, public_url: str = "", error: str = "", bytes_in: int = 0, bytes_out: int = 0) -> Layout:
        """create the live layout for the tunnel ui."""
        layout = Layout()
        
        # header
        header_text = Text()
        header_text.append("tunnelite", style="bold")
        header_text.append(" / ", style="dim")
        header_text.append(f"{tunnel_type} tunnel", style="dim")
        
        # status display
        if status == "active":
            status_text = Text(f"● active", style="green")
        elif status == "error":
            status_text = Text(f"✗ error", style="red")
        elif status == "disconnected":
            status_text = Text(f"○ disconnected", style="yellow")
        else:
            status_text = Text(f"○ {status}", style="dim")

        header_cols = Columns([
            Align.left(header_text),
            Align.right(status_text)
        ])
        
        layout.split(
            Layout(name="header", size=3),
            Layout(ratio=1, name="main"),
            Layout(size=3, name="footer")
        )

        # main section
        main_panel_content = []
        if public_url:
            main_panel_content.append(Text(f"     public: {public_url}", justify="left"))
        main_panel_content.append(Text(f"      local: 127.0.0.1:{local_port}", justify="left", style="dim"))
        
        if error:
            main_panel_content.append(Text())
            main_panel_content.append(Text(error, style="red", justify="left"))

        layout["main"].update(
            Align.center(
                Panel(
                    Layout(main_panel_content),
                    title="tunnel details",
                    border_style="dim",
                    width=60,
                    height=8
                )
            )
        )
        
        # footer (network activity)
        bytes_in_str = format_bytes(bytes_in)
        bytes_out_str = format_bytes(bytes_out)
        
        footer_text = Text()
        footer_text.append(f"in: {bytes_in_str}", style="dim")
        footer_text.append(" / ", style="dim")
        footer_text.append(f"out: {bytes_out_str}", style="dim")
        
        footer_cols = Columns([
            Align.left(Text(f"[dim]network log (last {max_network_events} events)")),
            Align.right(footer_text)
        ])
        
        # network event log
        event_log = Layout(
            [Layout(Text(format_network_event(e))) for e in network_events[-5:]]
        )
        
        footer_layout = Layout()
        footer_layout.split_column(
            Layout(footer_cols, name="footer_header"),
            Layout(event_log, name="event_log")
        )

        layout["footer"].update(
             Align.center(
                Panel(
                    footer_layout,
                    title="activity",
                    border_style="dim",
                    width=60,
                    height=10
                )
            )
        )
        
        # spinner for non-active states
        if status not in ["active", "error", "disconnected"]:
            layout["header"].update(
                 Columns([
                    Align.left(Spinner("dots", text=header_text)),
                    Align.right(status_text)
                ])
            )

        return layout
    
    def log_request(method: str, path: str, status_code: int, size: int, direction: str):
        """helper to log http request/response events"""
        if direction == "in":
            icon = "→"
            color = "blue"
        else:
            icon = "←"
            color = "green" if status_code < 400 else "red"
        
        msg = f"[{color}]{method} {path} - {status_code}[/{color}]"
        add_network_event("response", msg, {"status_code": status_code})

    with Live(make_layout("initializing..."), screen=True, auto_refresh=False) as live:
        try:
            # 1. create the tunnel on the server
            live.update(make_layout("requesting tunnel..."), refresh=True)
            headers = {"x-api-key": api_key}
            payload = {
                "tunnel_type": tunnel_type,
                "local_port": local_port,
            }
            response = requests.post(f"{main_server_url}/tunnels", json=payload, headers=headers, verify=certifi.where())

            if response.status_code == 401:
                live.update(make_layout("error", error="authentication failed. please check your api key."), refresh=True)
                return

            if response.status_code != 200:
                error_detail = "unknown error"
                try:
                    error_detail = response.json().get("detail", "unknown error")
                except:
                    pass
                live.update(make_layout("error", error=f"failed to create tunnel: {error_detail}"), refresh=True)
                return
            
            tunnel_data = response.json()
            tunnel_id = tunnel_data.get("id")
            public_url = tunnel_data.get("public_url")
            node_ws_url = tunnel_data.get("node_ws_url")
            
            if not all([tunnel_id, public_url, node_ws_url]):
                live.update(make_layout("error", error="server response missing required tunnel information."), refresh=True)
                return

            # 2. connect to the assigned tunnel node via websocket
            live.update(make_layout("connecting...", public_url=public_url), refresh=True)
            
            ws_url = f"{node_ws_url}/ws/connect"
            
            try:
                # establish the websocket connection
                websocket = await websockets.connect(ws_url, ssl=True)

                # activation handshake
                activation_message = {
                    "type": "activate",
                    "tunnel_id": tunnel_id,
                    "api_key": api_key
                }
                await websocket.send(json.dumps(activation_message))
                
                # wait for confirmation
                response_str = await websocket.recv()
                response_json = json.loads(response_str)

                if response_json.get("status") != "success":
                    error_msg = response_json.get("message", "tunnel activation failed")
                    live.update(make_layout("error", public_url=public_url, error=error_msg), refresh=True)
                    await websocket.close()
                    return

            except (websockets.exceptions.ConnectionClosed, websockets.exceptions.InvalidHandshake) as e:
                live.update(make_layout("error", public_url=public_url, error=f"websocket connection failed: {e}"), refresh=True)
                return
            except Exception as e:
                live.update(make_layout("error", public_url=public_url, error=f"an unexpected error occurred: {e}"), refresh=True)
                return
            
            live.update(make_layout("active", public_url=public_url), refresh=True)
            add_network_event("tunnel", "tunnel active", {"url": public_url})

            bytes_in = 0
            bytes_out = 0
            
            # --- nested functions for bidirectional forwarding ---

            async def forward_local_to_ws(sub_id: str, reader: asyncio.StreamReader):
                nonlocal bytes_out
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data:
                            await websocket.send(json.dumps({"type": "close_stream", "sub_id": sub_id}))
                            break
                        
                        bytes_out += len(data)
                        
                        # simple framing: [sub_id_len (1 byte)][sub_id][data]
                        sub_id_bytes = sub_id.encode('utf-8')
                        header = bytes([len(sub_id_bytes)]) + sub_id_bytes
                        await websocket.send(header + data)
                        
                        live.update(make_layout(
                            "active", 
                            public_url=public_url,
                            bytes_in=bytes_in,
                            bytes_out=bytes_out
                        ), refresh=True)
                except (ConnectionResetError, BrokenPipeError):
                    # local connection closed by client
                    pass
                except Exception as e:
                    add_network_event("error", f"local->ws error: {e}", {"sub_id": sub_id})
                finally:
                    # ensure stream is closed on this side
                    await websocket.send(json.dumps({"type": "close_stream", "sub_id": sub_id}))


            async def forward_ws_to_local_tcp(sub_id: str, writer: asyncio.StreamWriter):
                nonlocal bytes_in
                # this task is managed by the main ws receiver loop
                # it just needs to write data to the local socket
                # and handle closing the writer when done.
                try:
                    while True:
                        # this is a placeholder; the actual data receiving
                        # is handled by the main while loop below.
                        # we use an event to signal data arrival.
                        data_event = sub_connection_events.get(sub_id)
                        if not data_event:
                            break # connection closed
                        
                        data = await data_event.get()
                        if data is None: # None is the signal to close
                            break

                        writer.write(data)
                        await writer.drain()
                        bytes_in += len(data)
                        
                        live.update(make_layout(
                            "active", 
                            public_url=public_url,
                            bytes_in=bytes_in,
                            bytes_out=bytes_out
                        ), refresh=True)
                
                except (ConnectionResetError, BrokenPipeError):
                    # remote connection closed
                    pass
                except Exception as e:
                     add_network_event("error", f"ws->local error: {e}", {"sub_id": sub_id})
                finally:
                    if not writer.is_closing():
                        writer.close()
                        await writer.wait_closed()


            # main websocket receive loop
            try:
                while True:
                    message = await websocket.recv()
                    
                    if isinstance(message, str):
                        # handle control messages (json)
                        try:
                            msg_json = json.loads(message)
                            if msg_json.get("type") == "error":
                                add_network_event("error", msg_json.get("message", "unknown error from node"))
                            
                            # if we get a close stream message for a sub-connection, terminate it
                            if msg_json.get("type") == "close_stream":
                                sub_id_to_close = msg_json.get("sub_id")
                                if sub_id_to_close in sub_connections:
                                    writer, _, event = sub_connections.pop(sub_id_to_close, (None, None, None))
                                    if writer and not writer.is_closing():
                                        writer.close()
                                    if event:
                                        event.put_nowait(None) # signal closure
                                        
                        except json.JSONDecodeError:
                            add_network_event("error", "received non-json text message")

                    elif isinstance(message, bytes):
                        # handle data messages (binary)
                        header_len = 1
                        sub_id_len = message[0]
                        sub_id = message[header_len : header_len + sub_id_len].decode('utf-8')
                        data = message[header_len + sub_id_len:]

                        if sub_id not in sub_connections:
                            # new sub-connection
                            try:
                                reader, writer = await asyncio.open_connection('127.0.0.1', local_port)
                                data_event = asyncio.Queue()
                                
                                # create a task to forward from local to websocket
                                fwd_local_task = asyncio.create_task(forward_local_to_ws(sub_id, reader))
                                # create a task to forward from websocket to local
                                fwd_ws_task = asyncio.create_task(forward_ws_to_local_tcp(sub_id, writer))
                                
                                sub_connections[sub_id] = (writer, fwd_local_task, data_event)
                                
                                # put the first chunk of data into the queue
                                await data_event.put(data)
                                
                            except ConnectionRefusedError:
                                # failed to connect to local service
                                await websocket.send(json.dumps({
                                    "type": "error", 
                                    "sub_id": sub_id,
                                    "message": f"connection to 127.0.0.1:{local_port} refused"
                                }))
                                await websocket.send(json.dumps({"type": "close_stream", "sub_id": sub_id}))
                            except Exception as e:
                                await websocket.send(json.dumps({
                                    "type": "error", 
                                    "sub_id": sub_id,
                                    "message": f"failed to establish local connection: {e}"
                                }))
                                await websocket.send(json.dumps({"type": "close_stream", "sub_id": sub_id}))
                        
                        else:
                            # existing sub-connection, just queue the data
                            _, _, data_event = sub_connections[sub_id]
                            await data_event.put(data)


            except websockets.exceptions.ConnectionClosed:
                live.update(make_layout("disconnected", public_url=public_url), refresh=True)
            finally:
                # cleanup all sub-connections
                for sub_id, (writer, task, event) in sub_connections.items():
                    if task:
                        task.cancel()
                    if writer and not writer.is_closing():
                        writer.close()
                    if event:
                        event.put_nowait(None) # signal closure

                if 'websocket' in locals() and not websocket.closed:
                    await websocket.close()

        except requests.RequestException as e:
            live.update(make_layout("error", error=f"api request failed: {e}"), refresh=True)
        except KeyboardInterrupt:
            console.print("\n[bold yellow] a b o r t e d .[/bold yellow]")
        finally:
            # ensure we attempt to close the websocket connection on exit
            if 'websocket' in locals() and not websocket.closed:
                await websocket.close()
            
            # ensure all sub-connection tasks are cancelled
            for sub_id, (writer, task, event) in sub_connections.items():
                if task:
                    task.cancel()
                if writer and not writer.is_closing():
                    writer.close()
                if event:
                    event.put_nowait(None)


def register_user():
    """interactive prompt to register a new user."""
    clear_screen()
    show_header()
    console.print(Align.center("create a new account"), style="bold")
    console.print()
    
    email = Prompt.ask(" enter your email")
    
    try:
        payload = {"email": email}
        response = requests.post(f"{main_server_url}/users/register", json=payload, verify=certifi.where())
        
        if response.status_code == 200:
            console.print(" registration successful! please check your email for your api key.", style="green")
            console.print(" once you have your key, use the [bold]login[/bold] command.", style="dim")
        elif response.status_code == 409:
            console.print(" an account with this email already exists.", style="yellow")
        else:
            error_detail = response.json().get("detail", "an unknown error occurred")
            console.print(f" registration failed: {error_detail}", style="red")
            
    except requests.RequestException as e:
        console.print(f" error connecting to server: {e}", style="red")
    
    console.print()
    Prompt.ask("press enter to return to the main menu...")


def login_user():
    """interactive prompt to log in with an api key."""
    clear_screen()
    show_header()
    console.print(Align.center("log in with your api key"), style="bold")
    console.print()
    
    api_key = Prompt.ask(" paste your api key")
    
    # validate the api key with the server
    try:
        headers = {"x-api-key": api_key}
        response = requests.get(f"{main_server_url}/users/me", headers=headers, verify=certifi.where())
        
        if response.status_code == 200:
            save_api_key(api_key)
        else:
            console.print(" invalid api key.", style="red")
            
    except requests.RequestException as e:
        console.print(f" error connecting to server: {e}", style="red")

    console.print()
    Prompt.ask("press enter to return to the main menu...")


def view_tunnels():
    """view active tunnels for the current user."""
    clear_screen()
    show_header()
    console.print(Align.center("your active tunnels"), style="bold")
    console.print()
    
    api_key = get_api_key()
    if not api_key:
        console.print(" you must be logged in to view tunnels.", style="yellow")
        console.print()
        Prompt.ask("press enter to return...")
        return
        
    try:
        headers = {"x-api-key": api_key}
        response = requests.get(f"{main_server_url}/tunnels", headers=headers, verify=certifi.where())
        response.raise_for_status()
        
        tunnels = response.json()
        show_tunnel_status(tunnels)
        
    except requests.RequestException as e:
        console.print(f" error fetching tunnels: {e}", style="red")

    console.print()
    Prompt.ask("press enter to return to the main menu...")


def create_tunnel():
    """interactive prompt to create a new tunnel."""
    clear_screen()
    show_header()
    console.print(Align.center("create a new tunnel"), style="bold")
    console.print()

    api_key = get_api_key()
    if not api_key:
        console.print(" you must be logged in to create tunnels.", style="yellow")
        console.print()
        Prompt.ask("press enter to return...")
        return

    tunnel_type = Prompt.ask(" select tunnel type", choices=["http", "tcp"], default="http")
    local_port_str = Prompt.ask(" enter local port number", default="8000")
    
    try:
        local_port = int(local_port_str)
    except ValueError:
        console.print(" invalid port number.", style="red")
        console.print()
        Prompt.ask("press enter to return...")
        return
        
    if Confirm.ask(f" confirm: create a [bold]{tunnel_type}[/bold] tunnel for port [bold]{local_port}[/bold]?"):
        asyncio.run(run_tunnel(api_key, tunnel_type, local_port))
    
    # after the tunnel runner exits, we just return to the caller (main menu loop)
    # the runner handles all the UI itself via the Live display.
    # a final clear is good to reset the screen state.
    clear_screen()
    
def show_main_menu():
    """the main interactive menu loop for the tui."""
    while True:
        clear_screen()
        show_header()
        show_user_info()
        
        # fetch and show tunnels for authenticated users
        api_key = get_api_key()
        if api_key:
            try:
                headers = {"x-api-key": api_key}
                response = requests.get(f"{main_server_url}/tunnels", headers=headers, verify=certifi.where())
                if response.ok:
                    show_tunnel_status(response.json())
                else:
                    show_tunnel_status([])
            except requests.RequestException:
                show_tunnel_status([])
        else:
            show_tunnel_status([])
        
        console.print()
        
        menu_options = {
            "1": "create tunnel",
            "2": "manage account",
            "q": "quit"
        }
        
        # build menu text
        menu_items = [f"[bold][{key}][/bold] {text}" for key, text in menu_options.items()]
        menu_text = "   ".join(menu_items)
        
        console.print(menu_text, justify="center")
        choice = Prompt.ask("\n select an option", choices=list(menu_options.keys()), show_choices=False)

        if choice == "1":
            create_tunnel()
        elif choice == "2":
            # simple sub-menu for account management
            clear_screen()
            show_header()
            acc_choice = Prompt.ask("account actions", choices=["login", "register", "back"], default="back")
            if acc_choice == "login":
                login_user()
            elif acc_choice == "register":
                register_user()
        elif choice == "q":
            break

@app.command()
def tui():
    """launch the interactive terminal user interface."""
    show_main_menu()

@app.command()
def quick(
    tunnel_type: str = typer.Argument("http", help="tunnel type (http, tcp)"),
    port: int = typer.Argument(..., help="local port to expose")
):
    """create a tunnel quickly from the command line."""
    api_key = get_api_key()
    if not api_key:
        console.print(" error: you must be logged in to create a tunnel.", style="red")
        console.print(" use [bold]tunnelite tui[/bold] and follow the prompts to log in.", style="dim")
        raise typer.Exit(1)
    
    asyncio.run(run_tunnel(api_key, tunnel_type, port))


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    tunnelite main entry point.
    
    if no subcommand is given, it will default to launching the tui.
    """
    if ctx.invoked_subcommand is None:
        tui()

if __name__ == "__main__":
    app()
