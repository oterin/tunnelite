import time
import json
from typing import Dict, List, Optional
from collections import deque
from dataclasses import dataclass, asdict
from enum import Enum

class NetworkEventType(Enum):
    CONNECTION_OPEN = "connection_open"
    CONNECTION_CLOSE = "connection_close"
    DATA_TRANSFER = "data_transfer"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    TCP_PACKET = "tcp_packet"
    TUNNEL_ACTIVATE = "tunnel_activate"
    TUNNEL_DEACTIVATE = "tunnel_deactivate"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    NODE_STATUS = "node_status"

@dataclass
class NetworkEvent:
    timestamp: float
    event_type: NetworkEventType
    tunnel_id: Optional[str] = None
    client_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    bytes_transferred: int = 0
    direction: Optional[str] = None  # "in" or "out"
    protocol: Optional[str] = None
    port: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict] = None

    def to_dict(self):
        return asdict(self)

class NetworkLogger:
    def __init__(self, max_events: int = 1000):
        self.events: deque = deque(maxlen=max_events)
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "total_bytes_in": 0,
            "total_bytes_out": 0,
            "total_requests": 0,
            "errors_count": 0,
            "start_time": time.time()
        }
        
    def log_event(self, event: NetworkEvent):
        """log a network event and update stats"""
        self.events.append(event)
        self._update_stats(event)
        
        # format for console output
        self._print_event(event)
    
    def _update_stats(self, event: NetworkEvent):
        """update running statistics"""
        if event.event_type == NetworkEventType.CONNECTION_OPEN:
            self.stats["total_connections"] += 1
            self.stats["active_connections"] += 1
        elif event.event_type == NetworkEventType.CONNECTION_CLOSE:
            self.stats["active_connections"] = max(0, self.stats["active_connections"] - 1)
        elif event.event_type == NetworkEventType.DATA_TRANSFER:
            if event.direction == "in":
                self.stats["total_bytes_in"] += event.bytes_transferred
            elif event.direction == "out":
                self.stats["total_bytes_out"] += event.bytes_transferred
        elif event.event_type in [NetworkEventType.HTTP_REQUEST, NetworkEventType.HTTP_RESPONSE]:
            self.stats["total_requests"] += 1
        elif event.event_type == NetworkEventType.ERROR:
            self.stats["errors_count"] += 1
    
    def _print_event(self, event: NetworkEvent):
        """print formatted event to console"""
        timestamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        tunnel_short = event.tunnel_id[:8] if event.tunnel_id else "--------"
        
        if event.event_type == NetworkEventType.CONNECTION_OPEN:
            print(f"net:      [{timestamp}] {tunnel_short} connection opened from {event.client_ip}:{event.port}")
        
        elif event.event_type == NetworkEventType.CONNECTION_CLOSE:
            duration = event.metadata.get("duration", 0) if event.metadata else 0
            print(f"net:      [{timestamp}] {tunnel_short} connection closed (duration: {duration:.1f}s)")
        
        elif event.event_type == NetworkEventType.HTTP_REQUEST:
            print(f"net:      [{timestamp}] {tunnel_short} → {event.method} {event.path} ({event.bytes_transferred}b)")
        
        elif event.event_type == NetworkEventType.HTTP_RESPONSE:
            status_color = "✓" if event.status_code < 400 else "✗"
            print(f"net:      [{timestamp}] {tunnel_short} ← {status_color} {event.status_code} ({event.bytes_transferred}b)")
        
        elif event.event_type == NetworkEventType.TCP_PACKET:
            arrow = "→" if event.direction == "in" else "←"
            print(f"net:      [{timestamp}] {tunnel_short} {arrow} tcp packet ({event.bytes_transferred}b)")
        
        elif event.event_type == NetworkEventType.TUNNEL_ACTIVATE:
            print(f"net:      [{timestamp}] {tunnel_short} tunnel activated ({event.protocol})")
        
        elif event.event_type == NetworkEventType.TUNNEL_DEACTIVATE:
            print(f"net:      [{timestamp}] {tunnel_short} tunnel deactivated")
        
        elif event.event_type == NetworkEventType.ERROR:
            print(f"net:      [{timestamp}] {tunnel_short} ERROR: {event.error_message}")
        
        elif event.event_type == NetworkEventType.HEARTBEAT:
            active = event.metadata.get("active_tunnels", 0) if event.metadata else 0
            print(f"net:      [{timestamp}] -------- heartbeat sent (active tunnels: {active})")
    
    def get_recent_events(self, count: int = 50) -> List[NetworkEvent]:
        """get the most recent network events"""
        return list(self.events)[-count:]
    
    def get_events_by_tunnel(self, tunnel_id: str) -> List[NetworkEvent]:
        """get all events for a specific tunnel"""
        return [e for e in self.events if e.tunnel_id == tunnel_id]
    
    def get_stats(self) -> Dict:
        """get current networking statistics"""
        uptime = time.time() - self.stats["start_time"]
        return {
            **self.stats,
            "uptime_seconds": uptime,
            "bytes_per_second_in": self.stats["total_bytes_in"] / uptime if uptime > 0 else 0,
            "bytes_per_second_out": self.stats["total_bytes_out"] / uptime if uptime > 0 else 0,
            "requests_per_second": self.stats["total_requests"] / uptime if uptime > 0 else 0,
        }
    
    def get_formatted_log_for_tui(self, count: int = 15) -> List[str]:
        """get formatted log entries for TUI display"""
        recent_events = self.get_recent_events(count)
        formatted_lines = []
        
        for event in recent_events:
            timestamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            tunnel_short = event.tunnel_id[:8] if event.tunnel_id else "--------"
            
            if event.event_type == NetworkEventType.CONNECTION_OPEN:
                line = f"[dim]{timestamp}[/dim] [green]●[/green] {tunnel_short} connection from {event.client_ip}"
            
            elif event.event_type == NetworkEventType.CONNECTION_CLOSE:
                line = f"[dim]{timestamp}[/dim] [red]●[/red] {tunnel_short} disconnected"
            
            elif event.event_type == NetworkEventType.HTTP_REQUEST:
                line = f"[dim]{timestamp}[/dim] → [cyan]{event.method}[/cyan] {event.path} [dim]({event.bytes_transferred}b)[/dim]"
            
            elif event.event_type == NetworkEventType.HTTP_RESPONSE:
                if event.status_code < 300:
                    color = "green"
                elif event.status_code < 400:
                    color = "yellow"
                else:
                    color = "red"
                line = f"[dim]{timestamp}[/dim] ← [{color}]{event.status_code}[/{color}] [dim]({event.bytes_transferred}b)[/dim]"
            
            elif event.event_type == NetworkEventType.TCP_PACKET:
                arrow = "→" if event.direction == "in" else "←"
                line = f"[dim]{timestamp}[/dim] {arrow} [blue]tcp[/blue] [dim]({event.bytes_transferred}b)[/dim]"
            
            elif event.event_type == NetworkEventType.TUNNEL_ACTIVATE:
                line = f"[dim]{timestamp}[/dim] [bold green]▲[/bold green] {tunnel_short} tunnel activated"
            
            elif event.event_type == NetworkEventType.TUNNEL_DEACTIVATE:
                line = f"[dim]{timestamp}[/dim] [bold red]▼[/bold red] {tunnel_short} tunnel deactivated"
            
            elif event.event_type == NetworkEventType.ERROR:
                line = f"[dim]{timestamp}[/dim] [bold red]✗[/bold red] {event.error_message}"
            
            elif event.event_type == NetworkEventType.HEARTBEAT:
                active = event.metadata.get("active_tunnels", 0) if event.metadata else 0
                line = f"[dim]{timestamp}[/dim] [yellow]♥[/yellow] heartbeat (tunnels: {active})"
            
            else:
                line = f"[dim]{timestamp}[/dim] [dim]{event.event_type.value}[/dim]"
            
            formatted_lines.append(line)
        
        return formatted_lines

# global network logger instance
network_logger = NetworkLogger() 