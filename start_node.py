#!/usr/bin/env python3
"""
tunnelite node manager - beautiful tui for node setup and management
"""

import asyncio
import json
import os
import sys
import time
import uuid
import psutil
import platform
import socket
import requests
import uvicorn
import websockets
from typing import Optional, Dict, List
from multiprocessing import Process

# rich ui components
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.align import Align

# tunnelite imports
from tunnel_node.main import app as fastapi_app
from server import config as common_config

# --- configuration ---
home_dir = os.path.expanduser("~")
config_dir = os.path.join(home_dir, ".tunnelite-node")
api_key_file = os.path.join(config_dir, "user_api_key")
node_secret_file = os.path.join(config_dir, "node_secret_id")

# server configuration
MAIN_SERVER_URL = common_config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

# create console for rich output
console = Console()

# create the main cli application
app = typer.Typer(
    name="tunnelite-node",
    help="tunnelite node manager - host tunnels for users",
    add_completion=False,
)

# telemetry collection
telemetry_data = {
    "system": {},
    "network": {},
    "tunnels": {
        "active_tunnels": 0,
        "total_tunnels_served": 0,
        "http_requests_count": 0,
        "tcp_connections_count": 0,
        "data_transferred_mb": 0.0,
        "average_response_time_ms": 0.0,
        "error_rate_percent": 0.0
    }
}

def collect_system_metrics() -> Dict:
    """collect comprehensive system metrics"""
    try:
        # cpu and memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # load average (unix only)
        load_avg = [0.0, 0.0, 0.0]
        if hasattr(os, 'getloadavg'):
            load_avg = list(os.getloadavg())
        
        # uptime
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        return {
            "cpu_usage_percent": cpu_percent,
            "memory_usage_percent": memory.percent,
            "memory_total_mb": memory.total // (1024 * 1024),
            "memory_used_mb": memory.used // (1024 * 1024),
            "disk_usage_percent": disk.percent,
            "disk_total_gb": disk.total / (1024**3),
            "disk_used_gb": disk.used / (1024**3),
            "load_average_1m": load_avg[0],
            "load_average_5m": load_avg[1],
            "load_average_15m": load_avg[2],
            "uptime_seconds": int(uptime)
        }
    except Exception as e:
        console.print(f"[dim]warning: could not collect system metrics: {e}[/dim]")
        return {}

def collect_network_metrics() -> Dict:
    """collect network metrics"""
    try:
        net_io = psutil.net_io_counters()
        connections = len(psutil.net_connections())
        
        return {
            "bytes_sent": net_io.bytes_sent,
            "bytes_received": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_received": net_io.packets_recv,
            "connections_active": connections,
            "connections_total": connections,
            "bandwidth_usage_mbps": 0.0  # calculated over time
        }
    except Exception as e:
        console.print(f"[dim]warning: could not collect network metrics: {e}[/dim]")
        return {}

async def send_telemetry():
    """send telemetry data to server"""
    try:
        node_secret_id = get_node_secret_id()
        if not node_secret_id:
            return
        
        # collect current metrics
        system_metrics = collect_system_metrics()
        network_metrics = collect_network_metrics()
        
        if not system_metrics or not network_metrics:
            return
        
        telemetry_payload = {
            "system": system_metrics,
            "network": network_metrics,
            "tunnels": telemetry_data["tunnels"],
            "timestamp": time.time(),
            "node_version": "1.0.0"
        }
        
        headers = {"x-api-key": node_secret_id}
        response = requests.post(
            f"{MAIN_SERVER_URL}/telemetry/metrics",
            json=telemetry_payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        
    except Exception as e:
        # silently fail telemetry to avoid disrupting node operation
        pass

def get_user_api_key() -> Optional[str]:
    """get user api key from config"""
    if not os.path.exists(api_key_file):
        return None
    with open(api_key_file, "r") as f:
        return f.read().strip()

def save_user_api_key(api_key: str):
    """save user api key to config"""
    os.makedirs(config_dir, exist_ok=True)
    with open(api_key_file, "w") as f:
        f.write(api_key)

def get_node_secret_id() -> Optional[str]:
    """get or create node secret id"""
    if os.path.exists(node_secret_file):
        with open(node_secret_file, "r") as f:
            return f.read().strip()
    else:
        # generate new node secret id
        node_secret_id = str(uuid.uuid4())
        os.makedirs(config_dir, exist_ok=True)
        with open(node_secret_file, "w") as f:
            f.write(node_secret_id)
        return node_secret_id

def clear_screen():
    """clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_header():
    """show centered header"""
    header_text = Text()
    header_text.append("tunnelite", style="bold")
    header_text.append(" / ", style="dim")
    header_text.append("node manager", style="dim")
    
    console.print()
    console.print(Align.center(header_text))
    console.print(Align.center("─" * 40, style="dim"))
    console.print()

def show_auth_status():
    """show authentication status"""
    api_key = get_user_api_key()
    if api_key:
        # verify api key with server
        try:
            response = requests.get(f"{MAIN_SERVER_URL}/auth/users/me", 
                                  headers={"x-api-key": api_key}, timeout=5)
            if response.status_code == 200:
                username = response.json().get("username", "unknown")
                console.print(Align.center(f"[dim]authenticated as {username}[/dim]"))
            else:
                console.print(Align.center("[dim]authentication expired[/dim]"))
        except:
            console.print(Align.center("[dim]authentication error[/dim]"))
    else:
        console.print(Align.center("[dim]not authenticated[/dim]"))
    console.print()

def show_node_status():
    """show current node status"""
    node_secret_id = get_node_secret_id()
    
    try:
        headers = {"x-node-secret-id": node_secret_id}
        response = requests.get(f"{MAIN_SERVER_URL}/nodes/me", headers=headers, timeout=5)
        
        if response.status_code == 200:
            node_data = response.json()
            
            # create status table
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("property", style="dim")
            table.add_column("value")
            
            status_icon = "●" if node_data.get("status") == "active" else "○"
            table.add_row("status", f"{status_icon} {node_data.get('status', 'unknown')}")
            table.add_row("hostname", node_data.get("public_hostname", "not assigned"))
            table.add_row("location", node_data.get("verified_geolocation", {}).get("city", "unknown"))
            table.add_row("port range", node_data.get("port_range", "not configured"))
            table.add_row("max clients", str(node_data.get("max_clients", 0)))
            
            # system metrics if available
            if node_data.get("cpu_usage") is not None:
                table.add_row("cpu usage", f"{node_data.get('cpu_usage', 0):.1f}%")
            if node_data.get("memory_usage") is not None:
                table.add_row("memory usage", f"{node_data.get('memory_usage', 0):.1f}%")
            if node_data.get("active_tunnels") is not None:
                table.add_row("active tunnels", str(node_data.get("active_tunnels", 0)))
            
            console.print(Align.center(table))
        else:
            console.print(Align.center("[dim]node not registered[/dim]"))
            
    except requests.RequestException:
        console.print(Align.center("[dim]could not connect to server[/dim]"))

def login_user():
    """interactive user login"""
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
            response = requests.post(
                f"{MAIN_SERVER_URL}/auth/token",
                data={"username": username, "password": password},
                timeout=10
            )
            response.raise_for_status()
            api_key = response.json()["api_key"]
            save_user_api_key(api_key)
            progress.stop_task(task)
            console.print(Align.center("✓ login successful"))
                
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response and hasattr(e, 'response') else str(e)
            console.print(Align.center(f"✗ login failed: {error_msg}"))
    
    console.print()
    input("press enter to continue...")

def register_user():
    """interactive user registration"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]create tunnelite account[/bold]"))
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
        task = progress.add_task("  creating account...", total=None)
        
        try:
            response = requests.post(
                f"{MAIN_SERVER_URL}/auth/register",
                json={"username": username, "password": password},
                timeout=10
            )
            response.raise_for_status()
            progress.stop_task(task)
            console.print(Align.center("✓ account created successfully"))
            console.print(Align.center("[dim]you can now login with your credentials[/dim]"))
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response and hasattr(e, 'response') else str(e)
            console.print(Align.center(f"✗ registration failed: {error_msg}"))
    
    console.print()
    input("press enter to continue...")

async def register_node():
    """interactive node registration with beautiful ui"""
    clear_screen()
    show_header()
    
    user_api_key = get_user_api_key()
    if not user_api_key:
        console.print(Align.center("[dim]please login first[/dim]"))
        input("press enter to continue...")
        return
    
    console.print(Align.center("[bold]register this server as a node[/bold]"))
    console.print()
    
    # get node configuration
    console.print(Align.center("[dim]node configuration[/dim]"))
    console.print()
    
    max_clients = Prompt.ask("  maximum concurrent clients", default="10", console=console)
    port_range = Prompt.ask("  port range for tunnels (e.g., 8000-8100)", default="8000-8100", console=console)
    
    console.print()
    
    def make_layout(status: str, message: str = ""):
        """create registration progress layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # header
        header_content = Panel(
            Align.center(f"[bold]● {status}[/bold]"),
            box=box.SIMPLE,
            style="dim"
        )
        layout["header"].update(header_content)
        
        # main content
        if message:
            main_content = Panel(
                Align.center(f"[dim]{message}[/dim]"),
                title="registration",
                box=box.SIMPLE
            )
        else:
            main_content = Panel(
                Align.center(f"[dim]{status}...[/dim]"),
                title="registration",
                box=box.SIMPLE
            )
        layout["main"].update(main_content)
        
        # footer
        footer_content = Panel(
            Align.center("[dim]please wait...[/dim]"),
            box=box.SIMPLE,
            style="dim"
        )
        layout["footer"].update(footer_content)
        
        return layout

    with Live(make_layout("starting registration"), refresh_per_second=4) as live:
        try:
            node_secret_id = get_node_secret_id()
            
            # 1. initial heartbeat
            live.update(make_layout("sending initial heartbeat"))
            public_ip = await get_public_ip()
            if not public_ip:
                live.update(make_layout("error", "could not determine public ip"))
                await asyncio.sleep(3)
                return
            
            temp_address = f"http://{public_ip}:8201"
            heartbeat_response = requests.post(
                f"{MAIN_SERVER_URL}/nodes/register",
                json={"node_secret_id": node_secret_id, "public_address": temp_address},
                timeout=10
            )
            heartbeat_response.raise_for_status()
            
            # 2. start temporary server for challenges
            live.update(make_layout("starting temporary server"))
            temp_server_process = Process(target=run_temp_server, daemon=True)
            temp_server_process.start()
            await asyncio.sleep(2)
            
            # 3. websocket registration
            live.update(make_layout("connecting to registration service"))
            ws_uri = MAIN_SERVER_URL.replace("http", "ws", 1) + "/registration/ws/register-node"
            
            async with websockets.connect(ws_uri, ssl=True) as websocket:
                # send auth data
                await websocket.send(json.dumps({
                    "node_secret_id": node_secret_id,
                    "user_api_key": user_api_key,
                }))
                
                while True:
                    message_str = await websocket.recv()
                    message = json.loads(message_str)
                    msg_type = message.get("type")
                    
                    if msg_type == "reverse_benchmark":
                        live.update(make_layout("running bandwidth benchmark"))
                        benchmark_results = run_reverse_benchmark()
                        if not benchmark_results:
                            live.update(make_layout("error", "benchmark failed"))
                            await asyncio.sleep(3)
                            return
                        await websocket.send(json.dumps(benchmark_results))
                        
                    elif msg_type == "prompt":
                        prompt_msg = message.get("message", "")
                        if "max concurrent clients" in prompt_msg:
                            await websocket.send(json.dumps({"response": max_clients}))
                        elif "port range" in prompt_msg:
                            await websocket.send(json.dumps({"response": port_range}))
                        else:
                            # fallback for any other prompts
                            await websocket.send(json.dumps({"response": "default"}))
                            
                    elif msg_type == "challenge":
                        live.update(make_layout("verifying port accessibility"))
                        port = message.get('port')
                        key = message.get('key')
                        
                        # simple verification - just confirm ready
                        await websocket.send(json.dumps({"status": "ready"}))
                        
                    elif msg_type == "info":
                        info_msg = message.get('message', '')
                        live.update(make_layout("processing", info_msg))
                        
                    elif msg_type == "success":
                        success_msg = message.get('message', 'registration complete!')
                        live.update(make_layout("registration successful", success_msg))
                        await asyncio.sleep(2)
                        
                        # stop temp server
                        temp_server_process.terminate()
                        temp_server_process.join(timeout=5)
                        return
                        
                    elif msg_type == "failure":
                        error_msg = message.get('message', 'registration failed')
                        live.update(make_layout("registration failed", error_msg))
                        await asyncio.sleep(3)
                        
                        # stop temp server
                        temp_server_process.terminate()
                        temp_server_process.join(timeout=5)
                        return
                        
        except Exception as e:
            live.update(make_layout("error", str(e)))
            await asyncio.sleep(3)
            
            # cleanup temp server
            try:
                temp_server_process.terminate()
                temp_server_process.join(timeout=5)
            except:
                pass

async def get_public_ip():
    """get public ip address"""
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        response.raise_for_status()
        return response.json()["ip"]
    except:
        return None

def run_reverse_benchmark():
    """run bandwidth benchmark"""
    try:
        # download test
        down_url = f"{MAIN_SERVER_URL}/registration/benchmark/download"
        start_time = time.monotonic()
        with requests.get(down_url, stream=True, timeout=20) as r:
            r.raise_for_status()
            for _ in r.iter_content(chunk_size=8192): 
                pass
        down_duration = time.monotonic() - start_time
        down_mbps = (10 * 1024 * 1024 / down_duration) * 8 / (1024*1024)

        # upload test
        up_url = f"{MAIN_SERVER_URL}/registration/benchmark/upload"
        dummy_payload = b'\0' * (10 * 1024 * 1024)
        start_time = time.monotonic()
        r = requests.post(up_url, data=dummy_payload, timeout=20)
        r.raise_for_status()
        up_duration = time.monotonic() - start_time
        up_mbps = (10 * 1024 * 1024 / up_duration) * 8 / (1024*1024)

        return {"down_mbps": down_mbps, "up_mbps": up_mbps}
    except:
        return None

def run_temp_server():
    """run temporary server for registration challenges"""
    try:
        uvicorn.run(
            "tunnel_node.main:app",
            host="0.0.0.0",
            port=8201,
            log_level="warning",
            access_log=False
        )
    except:
        pass

async def start_node_production():
    """start node in production mode with ssl"""
    clear_screen()
    show_header()
    
    user_api_key = get_user_api_key()
    node_secret_id = get_node_secret_id()
    
    if not user_api_key or not node_secret_id:
        console.print(Align.center("[dim]node not configured - please register first[/dim]"))
        input("press enter to continue...")
        return
    
    def make_layout(status: str, details: str = "", error: str = ""):
        """create production server layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=7),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        if error:
            header_content = Panel(
                Align.center(f"[bold]● error[/bold]\n[dim]{error}[/dim]"),
                box=box.SIMPLE,
                style="dim"
            )
        elif status == "running":
            # show live metrics
            sys_metrics = collect_system_metrics()
            stats_text = f"[bold]tunnelite node[/bold] [dim]│[/dim] "
            stats_text += f"cpu: {sys_metrics.get('cpu_usage_percent', 0):.1f}% [dim]│[/dim] "
            stats_text += f"mem: {sys_metrics.get('memory_usage_percent', 0):.1f}% [dim]│[/dim] "
            stats_text += f"tunnels: {telemetry_data['tunnels']['active_tunnels']}"
            
            header_content = Panel(
                Align.center(stats_text),
                box=box.SIMPLE,
                style="bold"
            )
        else:
            header_content = Panel(
                Align.center(f"[bold]● {status}[/bold]"),
                box=box.SIMPLE,
                style="dim"
            )
        
        layout["header"].update(header_content)
        
        # main content
        if error:
            main_content = Panel(
                Align.center(f"[dim]{error}[/dim]"),
                title="error",
                box=box.SIMPLE
            )
        elif status == "running":
            main_content = Panel(
                Align.center(
                    f"[bold]node is running[/bold]\n\n"
                    f"[dim]hostname:[/dim] {details}\n"
                    f"[dim]status:[/dim] serving tunnels\n"
                    f"[dim]uptime:[/dim] {time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))}\n\n"
                    f"[dim]telemetry is being collected and sent to server[/dim]"
                ),
                title="production mode",
                box=box.SIMPLE
            )
        else:
            main_content = Panel(
                Align.center(f"[dim]{details or status}...[/dim]"),
                title="starting",
                box=box.SIMPLE
            )
        
        layout["main"].update(main_content)
        
        # footer
        footer_content = Panel(
            Align.center("[dim]press [bold]ctrl+c[/bold] to stop[/dim]"),
            box=box.SIMPLE,
            style="dim"
        )
        layout["footer"].update(footer_content)
        
        return layout

    with Live(make_layout("checking node status"), refresh_per_second=2) as live:
        try:
            # 1. verify node registration
            live.update(make_layout("verifying registration"))
            headers = {"x-node-secret-id": node_secret_id}
            response = requests.get(f"{MAIN_SERVER_URL}/nodes/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                live.update(make_layout("", "", "node not registered - please register first"))
                await asyncio.sleep(3)
                return
            
            node_data = response.json()
            hostname = node_data.get("public_hostname")
            
            if not hostname:
                live.update(make_layout("", "", "node registration incomplete"))
                await asyncio.sleep(3)
                return
            
            # 2. get public ip
            live.update(make_layout("getting public ip"))
            public_ip = await get_public_ip()
            if not public_ip:
                live.update(make_layout("", "", "could not determine public ip"))
                await asyncio.sleep(3)
                return
            
            # 3. request ssl certificate from server
            live.update(make_layout("requesting ssl certificate from server"))
            cert_response = requests.post(
                f"{MAIN_SERVER_URL}/internal/control/generate-ssl-certificate",
                json={"public_ip": public_ip},
                headers={"x-api-key": node_secret_id},
                timeout=300
            )
            cert_response.raise_for_status()
            
            cert_data = cert_response.json()
            if cert_data.get("status") != "success":
                live.update(make_layout("", "", f"ssl certificate failed: {cert_data}"))
                await asyncio.sleep(3)
                return
            
            # 4. save ssl certificates
            live.update(make_layout("saving ssl certificates"))
            ssl_cert = cert_data.get("ssl_certificate")
            ssl_key = cert_data.get("ssl_private_key")
            
            cert_dir = f"/etc/letsencrypt/live/{hostname}"
            os.makedirs(cert_dir, mode=0o755, exist_ok=True)
            
            cert_path = f"{cert_dir}/fullchain.pem"
            key_path = f"{cert_dir}/privkey.pem"
            
            with open(cert_path, 'w') as f:
                f.write(ssl_cert)
            os.chmod(cert_path, 0o644)
            
            with open(key_path, 'w') as f:
                f.write(ssl_key)
            os.chmod(key_path, 0o600)
            
            # 5. start production server
            live.update(make_layout("starting production server", hostname))
            
            # parse port range
            port_range_str = node_data.get("port_range", "8201")
            port_list = parse_port_range(port_range_str)
            main_port = port_list[0] if port_list else 8201
            
            # start telemetry collection
            start_time = time.time()
            
            # create uvicorn config
            config = uvicorn.Config(
                app=fastapi_app,
                host="0.0.0.0",
                port=main_port,
                ssl_keyfile=key_path,
                ssl_certfile=cert_path,
                access_log=True,
                log_level="info"
            )
            server = uvicorn.Server(config)
            
            # start telemetry task
            async def telemetry_task():
                while True:
                    await asyncio.sleep(60)  # send telemetry every minute
                    await send_telemetry()
            
            telemetry_task_handle = asyncio.create_task(telemetry_task())
            
            # update ui to running state
            live.update(make_layout("running", hostname))
            
            # run server
            try:
                await server.serve()
            except KeyboardInterrupt:
                telemetry_task_handle.cancel()
                live.update(make_layout("shutting down"))
                await asyncio.sleep(1)
                
        except requests.RequestException as e:
            error_msg = e.response.text if hasattr(e, 'response') and e.response else str(e)
            live.update(make_layout("", "", f"server error: {error_msg}"))
            await asyncio.sleep(3)
        except Exception as e:
            live.update(make_layout("", "", f"unexpected error: {e}"))
            await asyncio.sleep(3)

def parse_port_range(range_str: str) -> List[int]:
    """parse port range string into list of ports"""
    ports = []
    for part in range_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def show_main_menu():
    """show main menu"""
    clear_screen()
    show_header()
    show_auth_status()
    show_node_status()
    
    menu_items = [
        "1. start node",
        "2. register node", 
        "3. login",
        "4. register account",
        "5. exit"
    ]
    
    console.print(Align.center("[bold]node manager[/bold]"))
    console.print()
    
    for item in menu_items:
        console.print(Align.center(f"[dim]{item}[/dim]"))
    
    console.print()
    
    choice = Prompt.ask("  choose option", choices=["1", "2", "3", "4", "5"], console=console)
    
    if choice == "1":
        asyncio.run(start_node_production())
    elif choice == "2":
        asyncio.run(register_node())
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
    """start the interactive node manager tui"""
    try:
        while True:
            show_main_menu()
    except KeyboardInterrupt:
        console.print()
        console.print(Align.center("[dim]goodbye[/dim]"))

@app.command()
def start():
    """quickly start the node in production mode"""
    asyncio.run(start_node_production())

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """tunnelite node manager"""
    if ctx.invoked_subcommand is None:
        tui()

if __name__ == "__main__":
    app() 