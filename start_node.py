#!/usr/bin/env python3
"""
tunnelite node manager - minimalistic tui for node setup and management
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

# global node state for metrics and logging
node_state = {
    "start_time": None,
    "activity_log": [],
    "bandwidth_history": [],
    "tunnel_stats": {
        "active_tunnels": 0,
        "total_requests": 0,
        "data_transferred_mb": 0.0,
        "active_connections": 0
    },
    "ban_stats": {
        "total_bans": 0,
        "active_bans": 0,
        "recent_kicks": 0
    }
}

def add_activity_log(level: str, action: str, details: str = ""):
    """add timestamped activity entry"""
    global node_state
    timestamp = time.strftime("%H:%M:%S")
    entry = {"timestamp": timestamp, "level": level, "action": action, "details": details}
    node_state["activity_log"].append(entry)
    if len(node_state["activity_log"]) > 50:  # keep last 50 entries
        node_state["activity_log"].pop(0)

def format_bytes(bytes_val):
    """format bytes in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f}{unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f}TB"

def format_uptime(seconds):
    """format uptime in human readable format"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    return f"{hours:02d}:{minutes:02d}:{int(seconds % 60):02d}"

def collect_system_metrics() -> Dict:
    """collect comprehensive system metrics"""
    try:
        # cpu and memory
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # network io
        net_io = psutil.net_io_counters()
        
        # load average (unix only)
        load_avg = [0.0, 0.0, 0.0]
        if hasattr(os, 'getloadavg'):
            load_avg = list(os.getloadavg())
        
        # uptime
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # calculate bandwidth usage
        current_time = time.time()
        bandwidth_mbps = 0.0
        
        if node_state["bandwidth_history"]:
            last_entry = node_state["bandwidth_history"][-1]
            time_diff = current_time - last_entry["timestamp"]
            if time_diff > 0:
                bytes_diff = (net_io.bytes_sent + net_io.bytes_recv) - last_entry["total_bytes"]
                bandwidth_mbps = (bytes_diff * 8) / (time_diff * 1024 * 1024)  # convert to mbps
        
        # store bandwidth history
        node_state["bandwidth_history"].append({
            "timestamp": current_time,
            "total_bytes": net_io.bytes_sent + net_io.bytes_recv
        })
        
        # keep only last 60 entries (1 minute of history)
        if len(node_state["bandwidth_history"]) > 60:
            node_state["bandwidth_history"].pop(0)
        
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
            "uptime_seconds": int(uptime),
            "bandwidth_mbps": bandwidth_mbps,
            "connections_count": len(psutil.net_connections())
        }
    except Exception as e:
        console.print(f"[dim]warning: could not collect system metrics: {e}[/dim]")
        return {}

async def send_telemetry():
    """send telemetry data to server"""
    try:
        node_secret_id = get_node_secret_id()
        if not node_secret_id:
            return
        
        # collect current metrics
        system_metrics = collect_system_metrics()
        if not system_metrics:
            return
        
        telemetry_payload = {
            "system": system_metrics,
            "tunnels": node_state["tunnels"],
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
    """get user api key from config file"""
    if not os.path.exists(api_key_file):
        return None
    with open(api_key_file, "r") as f:
        return f.read().strip()

def save_user_api_key(api_key: str):
    """save user api key to config file"""
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
    """show minimalistic centered header"""
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
    """show node status with key metrics"""
    node_secret_id = get_node_secret_id()
    
    try:
        headers = {"x-node-secret-id": node_secret_id}
        response = requests.get(f"{MAIN_SERVER_URL}/nodes/me", headers=headers, timeout=5)
        
        if response.status_code == 200:
            node_data = response.json()
            
            # create simple status table
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("key", style="dim", width=15)
            table.add_column("value", width=25)
            
            # basic info
            status = node_data.get("status", "unknown")
            hostname = node_data.get("public_hostname", "not assigned")
            location_data = node_data.get("verified_geolocation", {})
            location = f"{location_data.get('city', 'unknown')}, {location_data.get('countryCode', 'XX')}"
            
            table.add_row("status", f"● {status}")
            table.add_row("hostname", hostname)
            table.add_row("location", location)
            
            # metrics if available
            metrics = collect_system_metrics()
            if metrics:
                cpu_usage = metrics.get("cpu_usage_percent", 0)
                memory_usage = metrics.get("memory_usage_percent", 0)
                bandwidth = metrics.get("bandwidth_mbps", 0)
                
                table.add_row("cpu", f"{cpu_usage:.1f}%")
                table.add_row("memory", f"{memory_usage:.1f}%")
                table.add_row("bandwidth", f"{bandwidth:.2f} mbps")
                
                # tunnel stats
                active_tunnels = node_state["tunnel_stats"]["active_tunnels"]
                total_requests = node_state["tunnel_stats"]["total_requests"]
                table.add_row("tunnels", f"{active_tunnels} active")
                table.add_row("requests", str(total_requests))
                
                # ban stats
                ban_stats = node_state["ban_stats"]
                table.add_row("bans", f"{ban_stats['active_bans']} active")
            
            console.print(Align.center(table))
        else:
            console.print(Align.center("[dim]node not registered[/dim]"))
            
    except requests.RequestException:
        console.print(Align.center("[dim]connection error[/dim]"))
    
    console.print()

def show_ban_management():
    """show ban management interface for node owners"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]ban management[/bold]"))
    console.print()
    
    # check if user is authenticated and owns the node
    api_key = get_user_api_key()
    node_secret_id = get_node_secret_id()
    
    if not api_key:
        console.print(Align.center("[dim]please login first[/dim]"))
        input("press enter to continue...")
        return
    
    try:
        # verify node ownership
        headers = {"x-node-secret-id": node_secret_id}
        response = requests.get(f"{MAIN_SERVER_URL}/nodes/me", headers=headers, timeout=5)
        
        if response.status_code != 200:
            console.print(Align.center("[dim]node not registered[/dim]"))
            input("press enter to continue...")
            return
        
        node_data = response.json()
        node_owner = node_data.get("owner_username")
        
        # get current user
        user_response = requests.get(f"{MAIN_SERVER_URL}/auth/users/me", 
                                   headers={"x-api-key": api_key}, timeout=5)
        if user_response.status_code != 200:
            console.print(Align.center("[dim]authentication error[/dim]"))
            input("press enter to continue...")
            return
        
        current_user = user_response.json().get("username")
        
        if current_user != node_owner:
            console.print(Align.center("[dim]you don't own this node[/dim]"))
            input("press enter to continue...")
            return
        
        # show ban menu
        menu_items = [
            "1. view active bans",
            "2. ban user from node", 
            "3. tempban user",
            "4. kick user",
            "5. remove ban",
            "6. back to main menu"
        ]
        
        for item in menu_items:
            console.print(Align.center(f"[dim]{item}[/dim]"))
        
        console.print()
        choice = Prompt.ask("  choose option", choices=["1", "2", "3", "4", "5", "6"], console=console)
        
        if choice == "1":
            show_active_bans(node_secret_id, api_key)
        elif choice == "2":
            create_node_ban(node_secret_id, api_key, "permban")
        elif choice == "3":
            create_node_ban(node_secret_id, api_key, "tempban")
        elif choice == "4":
            kick_user_from_node(node_secret_id, api_key)
        elif choice == "5":
            remove_node_ban(node_secret_id, api_key)
        elif choice == "6":
            return
            
    except requests.RequestException as e:
        console.print(Align.center(f"[dim]error: {e}[/dim]"))
        input("press enter to continue...")

def show_active_bans(node_id: str, api_key: str):
    """show active bans for this node"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]active bans[/bold]"))
    console.print()
    
    try:
        headers = {"x-api-key": api_key}
        response = requests.post(
            f"{MAIN_SERVER_URL}/admin/nodes/{node_id}/bans/list",
            json={"active_only": True},
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            bans = response.json().get("bans", [])
            
            if not bans:
                console.print(Align.center("[dim]no active bans[/dim]"))
            else:
                table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
                table.add_column("target", style="dim")
                table.add_column("type")
                table.add_column("reason")
                table.add_column("expires", style="dim")
                
                for ban in bans:
                    target = ban.get("target_username") or ban.get("target_ip", "unknown")
                    ban_type = ban.get("ban_type", "unknown")
                    reason = ban.get("reason", "")[:30] + "..." if len(ban.get("reason", "")) > 30 else ban.get("reason", "")
                    expires = ban.get("expires_at", "never")[:10] if ban.get("expires_at") else "never"
                    
                    table.add_row(target, ban_type, reason, expires)
                
                console.print(Align.center(table))
        else:
            console.print(Align.center(f"[dim]error: {response.text}[/dim]"))
            
    except requests.RequestException as e:
        console.print(Align.center(f"[dim]error: {e}[/dim]"))
    
    console.print()
    input("press enter to continue...")

def create_node_ban(node_id: str, api_key: str, ban_type: str):
    """create a ban for this node"""
    clear_screen()
    show_header()
    
    console.print(Align.center(f"[bold]{ban_type} user[/bold]"))
    console.print()
    
    # get target info
    target_type = Prompt.ask("  ban by", choices=["ip", "username", "both"], default="username")
    
    target_ip = None
    target_username = None
    
    if target_type in ["ip", "both"]:
        target_ip = Prompt.ask("  ip address")
    
    if target_type in ["username", "both"]:
        target_username = Prompt.ask("  username")
    
    reason = Prompt.ask("  reason", default="violating node rules")
    
    duration_minutes = None
    if ban_type == "tempban":
        duration_hours = int(Prompt.ask("  duration (hours)", default="24"))
        duration_minutes = duration_hours * 60
    
    console.print()
    
    try:
        headers = {"x-api-key": api_key}
        payload = {
            "ban_type": ban_type,
            "ban_target": target_type,
            "reason": reason,
            "target_ip": target_ip,
            "target_username": target_username,
            "duration_minutes": duration_minutes
        }
        
        response = requests.post(
            f"{MAIN_SERVER_URL}/admin/nodes/{node_id}/bans/create",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            console.print(Align.center("✓ ban created successfully"))
            node_state["ban_stats"]["active_bans"] += 1
            add_activity_log("info", f"{ban_type} created", f"target: {target_username or target_ip}")
        else:
            console.print(Align.center(f"✗ error: {response.text}"))
            
    except requests.RequestException as e:
        console.print(Align.center(f"✗ error: {e}"))
    
    console.print()
    input("press enter to continue...")

def kick_user_from_node(node_id: str, api_key: str):
    """kick a user from this node"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]kick user[/bold]"))
    console.print()
    
    # get target info
    target_type = Prompt.ask("  kick by", choices=["ip", "username"], default="username")
    
    target_ip = None
    target_username = None
    
    if target_type == "ip":
        target_ip = Prompt.ask("  ip address")
    else:
        target_username = Prompt.ask("  username")
    
    reason = Prompt.ask("  reason", default="disruptive behavior")
    
    console.print()
    
    try:
        headers = {"x-api-key": api_key}
        payload = {
            "ip_address": target_ip,
            "username": target_username,
            "reason": reason
        }
        
        response = requests.post(
            f"{MAIN_SERVER_URL}/admin/nodes/{node_id}/bans/kick",
            json=payload,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            console.print(Align.center("✓ user kicked successfully"))
            node_state["ban_stats"]["recent_kicks"] += 1
            add_activity_log("info", "user kicked", f"target: {target_username or target_ip}")
        else:
            console.print(Align.center(f"✗ error: {response.text}"))
            
    except requests.RequestException as e:
        console.print(Align.center(f"✗ error: {e}"))
    
    console.print()
    input("press enter to continue...")

def remove_node_ban(node_id: str, api_key: str):
    """remove a ban from this node"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]remove ban[/bold]"))
    console.print()
    
    # first show current bans
    try:
        headers = {"x-api-key": api_key}
        response = requests.post(
            f"{MAIN_SERVER_URL}/admin/nodes/{node_id}/bans/list",
            json={"active_only": True},
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            bans = response.json().get("bans", [])
            
            if not bans:
                console.print(Align.center("[dim]no active bans to remove[/dim]"))
                input("press enter to continue...")
                return
            
            # show numbered list
            for i, ban in enumerate(bans, 1):
                target = ban.get("target_username") or ban.get("target_ip", "unknown")
                reason = ban.get("reason", "")[:30]
                console.print(Align.center(f"[dim]{i}. {target} - {reason}[/dim]"))
            
            console.print()
            choice = int(Prompt.ask("  select ban to remove", choices=[str(i) for i in range(1, len(bans) + 1)]))
            selected_ban = bans[choice - 1]
            
            # remove the ban
            remove_response = requests.delete(
                f"{MAIN_SERVER_URL}/admin/nodes/{node_id}/bans/{selected_ban['id']}",
                headers=headers,
                timeout=10
            )
            
            if remove_response.status_code == 200:
                console.print(Align.center("✓ ban removed successfully"))
                node_state["ban_stats"]["active_bans"] -= 1
                add_activity_log("info", "ban removed", f"target: {selected_ban.get('target_username') or selected_ban.get('target_ip')}")
            else:
                console.print(Align.center(f"✗ error: {remove_response.text}"))
        else:
            console.print(Align.center(f"[dim]error: {response.text}[/dim]"))
            
    except (requests.RequestException, ValueError) as e:
        console.print(Align.center(f"[dim]error: {e}[/dim]"))
    
    console.print()
    input("press enter to continue...")

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
    """register this server as a tunnelite node"""
    clear_screen()
    show_header()
    
    console.print(Align.center("[bold]register node[/bold]"))
    console.print()
    
    api_key = get_user_api_key()
    if not api_key:
        console.print(Align.center("[dim]please login first[/dim]"))
        input("press enter to continue...")
        return
    
    # get registration details
    hostname = Prompt.ask("  hostname", default="auto-detect")
    port_range = Prompt.ask("  port range", default="8201-8300")
    max_clients = int(Prompt.ask("  max clients", default="100"))
    
    console.print()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console
    ) as progress:
        task = progress.add_task("  registering node...", total=None)
        
        try:
            node_secret_id = get_node_secret_id()
            
            # get public ip if hostname is auto-detect
            if hostname == "auto-detect":
                progress.update(task, description="  detecting public ip...")
                public_ip = await get_public_ip()
                if not public_ip:
                    progress.stop_task(task)
                    console.print(Align.center("✗ could not detect public ip"))
                    input("press enter to continue...")
                    return
                hostname = f"{public_ip}.nip.io"
            
            progress.update(task, description="  registering with server...")
            
            payload = {
                "node_secret_id": node_secret_id,
                "public_hostname": hostname,
                "port_range": port_range,
                "max_clients": max_clients,
                "user_api_key": api_key
            }
            
            response = requests.post(
                f"{MAIN_SERVER_URL}/nodes/register",
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            
            progress.stop_task(task)
            console.print(Align.center("✓ node registered successfully"))
            console.print(Align.center(f"[dim]hostname: {hostname}[/dim]"))
            add_activity_log("success", "node registered", f"hostname: {hostname}")
            
        except requests.RequestException as e:
            progress.stop_task(task)
            error_msg = e.response.text if e.response and hasattr(e, 'response') else str(e)
            console.print(Align.center(f"✗ registration failed: {error_msg}"))
    
    console.print()
    input("press enter to continue...")

async def get_public_ip():
    """get public ip address"""
    try:
        response = requests.get("https://api.ipify.org", timeout=10)
        response.raise_for_status()
        return response.text.strip()
    except:
        return None

async def start_node_production():
    """start node in production mode with comprehensive monitoring"""
    
    def make_layout(status: str, details: str = "", error: str = ""):
        """create beautiful centered layout for production server"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # header
        if error:
            header_content = Panel(
                Align.center(f"[bold]✗ {error}[/bold]"),
                box=box.SIMPLE,
                style="red"
            )
        elif status == "running":
            uptime = time.time() - node_state["start_time"] if node_state["start_time"] else 0
            uptime_str = format_uptime(uptime)
            
            header_items = [
                "[bold]tunnelite node[/bold]",
                f"[dim]{details}[/dim]",
                f"uptime: {uptime_str}"
            ]
            
            header_content = Panel(
                Align.center(" • ".join(header_items)),
                box=box.SIMPLE
            )
        else:
            header_content = Panel(
                Align.center(f"[bold]● {status}[/bold]"),
                box=box.SIMPLE,
                style="dim"
            )
        
        layout["header"].update(header_content)
        
        # main area - split into metrics and activity
        if status == "running":
            layout["main"].split_row(
                Layout(name="metrics", ratio=2),
                Layout(name="activity", ratio=1)
            )
            
            # metrics table
            metrics = collect_system_metrics()
            metrics_table = Table(box=box.SIMPLE, show_header=False)
            metrics_table.add_column("metric", style="dim", width=12)
            metrics_table.add_column("value", width=15)
            
            if metrics:
                cpu_usage = metrics.get("cpu_usage_percent", 0)
                cpu_color = "red" if cpu_usage > 80 else "yellow" if cpu_usage > 60 else "green"
                metrics_table.add_row("cpu", f"[{cpu_color}]{cpu_usage:.1f}%[/{cpu_color}]")
                
                memory_usage = metrics.get("memory_usage_percent", 0)
                memory_color = "red" if memory_usage > 80 else "yellow" if memory_usage > 60 else "green"
                memory_used = format_bytes(metrics.get("memory_used_mb", 0) * 1024 * 1024)
                memory_total = format_bytes(metrics.get("memory_total_mb", 0) * 1024 * 1024)
                metrics_table.add_row("memory", f"[{memory_color}]{memory_usage:.1f}%[/{memory_color}]")
                metrics_table.add_row("", f"[dim]{memory_used}/{memory_total}[/dim]")
                
                bandwidth = metrics.get("bandwidth_mbps", 0)
                bandwidth_color = "green" if bandwidth > 0 else "dim"
                metrics_table.add_row("bandwidth", f"[{bandwidth_color}]{bandwidth:.2f} mbps[/{bandwidth_color}]")
                
                connections = metrics.get("connections_count", 0)
                metrics_table.add_row("connections", str(connections))
                
                # tunnel stats
                tunnel_stats = node_state["tunnel_stats"]
                metrics_table.add_row("tunnels", f"{tunnel_stats['active_tunnels']} active")
                metrics_table.add_row("requests", str(tunnel_stats["total_requests"]))
                metrics_table.add_row("data", format_bytes(tunnel_stats["data_transferred_mb"] * 1024 * 1024))
                
                # ban stats
                ban_stats = node_state["ban_stats"]
                metrics_table.add_row("bans", f"{ban_stats['active_bans']} active")
            
            metrics_panel = Panel(
                metrics_table,
                title="metrics",
                box=box.SIMPLE
            )
            layout["metrics"].update(metrics_panel)
            
            # activity log
            activity_lines = []
            for entry in node_state["activity_log"][-10:]:  # last 10 entries
                timestamp = entry["timestamp"]
                level = entry["level"]
                action = entry["action"]
                details = entry["details"]
                
                # format with simple icons
                if level == "success":
                    icon = "✓"
                elif level == "error":
                    icon = "✗"
                elif level == "warning":
                    icon = "!"
                else:
                    icon = "•"
                
                if details:
                    line = f"[dim]{timestamp}[/dim] {icon} {action} [dim]({details})[/dim]"
                else:
                    line = f"[dim]{timestamp}[/dim] {icon} {action}"
                
                activity_lines.append(line)
            
            if not activity_lines:
                activity_content = "[dim]waiting for activity...[/dim]"
            else:
                activity_content = "\n".join(activity_lines)
            
            activity_panel = Panel(
                activity_content,
                title="activity",
                box=box.SIMPLE,
                style="dim"
            )
            layout["activity"].update(activity_panel)
        else:
            # simple status display
            if details:
                content = f"[dim]{details}[/dim]"
            else:
                content = f"[dim]{status}...[/dim]"
            
            status_panel = Panel(
                Align.center(content),
                box=box.SIMPLE
            )
            layout["main"].update(status_panel)
        
        # footer
        footer_content = Panel(
            Align.center("[dim]press [bold]ctrl+c[/bold] to stop[/dim]"),
            box=box.SIMPLE,
            style="dim"
        )
        layout["footer"].update(footer_content)
        
        return layout

    with Live(make_layout("starting"), refresh_per_second=2) as live:
        try:
            # 1. verify node registration
            live.update(make_layout("verifying node"))
            add_activity_log("info", "verifying node registration")
            
            node_secret_id = get_node_secret_id()
            headers = {"x-node-secret-id": node_secret_id}
            response = requests.get(f"{MAIN_SERVER_URL}/nodes/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                live.update(make_layout("", "", "node not registered - please register first"))
                await asyncio.sleep(3)
                return
            
            node_data = response.json()
            hostname = node_data.get("public_hostname", "unknown")
            add_activity_log("success", "node verified", f"hostname: {hostname}")
            
            # 2. get public ip
            live.update(make_layout("getting public ip"))
            add_activity_log("info", "getting public ip")
            public_ip = await get_public_ip()
            if not public_ip:
                add_activity_log("error", "ip detection failed")
                live.update(make_layout("", "", "could not determine public ip"))
                await asyncio.sleep(3)
                return
            
            add_activity_log("success", "public ip detected", f"ip: {public_ip}")
            
            # 3. request ssl certificate from server
            live.update(make_layout("requesting ssl certificate"))
            add_activity_log("info", "requesting ssl certificate")
            cert_response = requests.post(
                f"{MAIN_SERVER_URL}/internal/control/generate-ssl-certificate",
                json={"public_ip": public_ip},
                headers={"x-api-key": node_secret_id},
                timeout=300
            )
            cert_response.raise_for_status()
            
            cert_data = cert_response.json()
            if cert_data.get("status") != "success":
                add_activity_log("error", "ssl certificate failed", str(cert_data))
                live.update(make_layout("", "", f"ssl certificate failed: {cert_data}"))
                await asyncio.sleep(3)
                return
            
            add_activity_log("success", "ssl certificate received")
            
            # 4. save ssl certificates
            live.update(make_layout("saving ssl certificates"))
            add_activity_log("info", "saving ssl certificates")
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
            live.update(make_layout("starting production server"))
            add_activity_log("info", "ssl certificates configured")
            
            # parse port range
            port_range_str = node_data.get("port_range", "8201")
            port_list = parse_port_range(port_range_str)
            main_port = port_list[0] if port_list else 8201
            
            # initialize node state
            node_state["start_time"] = time.time()
            add_activity_log("success", "node starting up", f"port: {main_port}")
            
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
            
            async def metrics_task():
                while True:
                    await asyncio.sleep(5)  # update metrics every 5 seconds
                    collect_system_metrics()
            
            telemetry_task_handle = asyncio.create_task(telemetry_task())
            metrics_task_handle = asyncio.create_task(metrics_task())
            
            add_activity_log("success", "production server started", f"https://{hostname}:{main_port}")
            
            # update ui to running state
            live.update(make_layout("running", hostname))
            
            # run server
            try:
                await server.serve()
            except KeyboardInterrupt:
                add_activity_log("info", "shutdown requested")
                telemetry_task_handle.cancel()
                metrics_task_handle.cancel()
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
    """show minimalistic main menu"""
    clear_screen()
    show_header()
    show_auth_status()
    show_node_status()
    
    # simple menu
    menu_items = [
        "1. start node",
        "2. register node",
        "3. ban management",
        "4. login",
        "5. register account",
        "6. exit"
    ]
    
    for item in menu_items:
        console.print(Align.center(f"[dim]{item}[/dim]"))
    
    console.print()
    
    choice = Prompt.ask("  choose option", choices=["1", "2", "3", "4", "5", "6"], console=console)
    
    if choice == "1":
        asyncio.run(start_node_production())
    elif choice == "2":
        asyncio.run(register_node())
    elif choice == "3":
        show_ban_management()
    elif choice == "4":
        login_user()
    elif choice == "5":
        register_user()
    elif choice == "6":
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
    # check for admin privileges on systems that support it
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        console.print(Align.center("[red]error: this script must be run as root[/red]"))
        sys.exit(1)
    
    if ctx.invoked_subcommand is None:
        tui()

if __name__ == "__main__":
    app() 