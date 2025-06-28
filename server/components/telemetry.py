import time
import json
from typing import Dict, List, Optional
from fastapi import APIRouter, Request, Depends, HTTPException, status
from pydantic import BaseModel, Field

from server.components import database
from server.components.auth import get_node_from_api_key, get_current_user

router = APIRouter(prefix="/telemetry", tags=["telemetry"])

class SystemMetrics(BaseModel):
    cpu_usage_percent: float = Field(..., ge=0, le=100)
    memory_usage_percent: float = Field(..., ge=0, le=100)
    memory_total_mb: int = Field(..., gt=0)
    memory_used_mb: int = Field(..., ge=0)
    disk_usage_percent: float = Field(..., ge=0, le=100)
    disk_total_gb: float = Field(..., gt=0)
    disk_used_gb: float = Field(..., ge=0)
    load_average_1m: float = Field(..., ge=0)
    load_average_5m: float = Field(..., ge=0)
    load_average_15m: float = Field(..., ge=0)
    uptime_seconds: int = Field(..., ge=0)

class NetworkMetrics(BaseModel):
    bytes_sent: int = Field(..., ge=0)
    bytes_received: int = Field(..., ge=0)
    packets_sent: int = Field(..., ge=0)
    packets_received: int = Field(..., ge=0)
    connections_active: int = Field(..., ge=0)
    connections_total: int = Field(..., ge=0)
    bandwidth_usage_mbps: float = Field(..., ge=0)

class TunnelMetrics(BaseModel):
    active_tunnels: int = Field(..., ge=0)
    total_tunnels_served: int = Field(..., ge=0)
    http_requests_count: int = Field(..., ge=0)
    tcp_connections_count: int = Field(..., ge=0)
    data_transferred_mb: float = Field(..., ge=0)
    average_response_time_ms: float = Field(..., ge=0)
    error_rate_percent: float = Field(..., ge=0, le=100)

class TelemetryData(BaseModel):
    system: SystemMetrics
    network: NetworkMetrics
    tunnels: TunnelMetrics
    timestamp: float = Field(default_factory=time.time)
    node_version: str = "1.0.0"

class TunnelEvent(BaseModel):
    event_type: str  # "created", "activated", "deactivated", "error", "request", "response"
    tunnel_id: str
    tunnel_type: str  # "http", "tcp", "udp"
    user_agent: Optional[str] = None
    source_ip: Optional[str] = None
    request_method: Optional[str] = None
    request_path: Optional[str] = None
    response_status: Optional[int] = None
    response_time_ms: Optional[float] = None
    bytes_transferred: Optional[int] = None
    error_message: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)

@router.post("/metrics")
async def submit_telemetry(
    telemetry: TelemetryData,
    node: dict = Depends(get_node_from_api_key)
):
    """nodes submit comprehensive telemetry data"""
    node_secret_id = node["node_secret_id"]
    
    # store telemetry in database with retention
    telemetry_record = {
        "node_secret_id": node_secret_id,
        "hostname": node.get("public_hostname", "unknown"),
        "timestamp": telemetry.timestamp,
        "system_metrics": telemetry.system.model_dump(),
        "network_metrics": telemetry.network.model_dump(),
        "tunnel_metrics": telemetry.tunnels.model_dump(),
        "node_version": telemetry.node_version
    }
    
    database.store_telemetry(telemetry_record)
    
    # update node with latest metrics summary
    node_update = {
        "node_secret_id": node_secret_id,
        "last_telemetry_at": telemetry.timestamp,
        "cpu_usage": telemetry.system.cpu_usage_percent,
        "memory_usage": telemetry.system.memory_usage_percent,
        "active_tunnels": telemetry.tunnels.active_tunnels,
        "total_data_transferred_mb": telemetry.tunnels.data_transferred_mb,
        "last_seen_at": time.time()
    }
    database.upsert_node(node_update)
    
    return {"status": "success", "message": "telemetry received"}

@router.post("/events")
async def submit_tunnel_events(
    events: List[TunnelEvent],
    node: dict = Depends(get_node_from_api_key)
):
    """nodes submit tunnel activity events"""
    node_secret_id = node["node_secret_id"]
    
    for event in events:
        event_record = {
            "node_secret_id": node_secret_id,
            "hostname": node.get("public_hostname", "unknown"),
            "event_type": event.event_type,
            "tunnel_id": event.tunnel_id,
            "tunnel_type": event.tunnel_type,
            "user_agent": event.user_agent,
            "source_ip": event.source_ip,
            "request_method": event.request_method,
            "request_path": event.request_path,
            "response_status": event.response_status,
            "response_time_ms": event.response_time_ms,
            "bytes_transferred": event.bytes_transferred,
            "error_message": event.error_message,
            "timestamp": event.timestamp
        }
        database.store_tunnel_event(event_record)
    
    return {"status": "success", "message": f"received {len(events)} events"}

@router.get("/nodes/{node_id}/metrics")
async def get_node_metrics(
    node_id: str,
    hours: int = 24,
    current_user: dict = Depends(get_current_user)
):
    """get telemetry data for a specific node (only for node owner)"""
    # get node to check ownership
    node = database.get_node_by_secret_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    
    # check if user owns this node
    if node.get("owner_username") != current_user["username"]:
        raise HTTPException(status_code=403, detail="you can only view metrics for your own nodes")
    
    # get telemetry data for the specified time range
    since_timestamp = time.time() - (hours * 3600)
    metrics = database.get_telemetry_for_node(node_id, since_timestamp)
    
    return {
        "node_hostname": node.get("public_hostname"),
        "owner": node.get("owner_username"),
        "metrics": metrics,
        "time_range_hours": hours
    }

@router.get("/nodes/{node_id}/events")
async def get_node_events(
    node_id: str,
    hours: int = 24,
    event_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """get tunnel events for a specific node (only for node owner)"""
    # get node to check ownership
    node = database.get_node_by_secret_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    
    # check if user owns this node
    if node.get("owner_username") != current_user["username"]:
        raise HTTPException(status_code=403, detail="you can only view events for your own nodes")
    
    # get events for the specified time range
    since_timestamp = time.time() - (hours * 3600)
    events = database.get_tunnel_events_for_node(node_id, since_timestamp, event_type)
    
    return {
        "node_hostname": node.get("public_hostname"),
        "owner": node.get("owner_username"),
        "events": events,
        "time_range_hours": hours,
        "event_type_filter": event_type
    }

@router.get("/my-nodes")
async def get_my_nodes_telemetry(
    current_user: dict = Depends(get_current_user)
):
    """get summary telemetry for all nodes owned by the current user"""
    username = current_user["username"]
    user_nodes = database.get_nodes_by_owner(username)
    
    nodes_summary = []
    for node in user_nodes:
        node_id = node["node_secret_id"]
        
        # get latest telemetry
        latest_metrics = database.get_latest_telemetry_for_node(node_id)
        
        # get activity summary for last 24 hours
        since_24h = time.time() - (24 * 3600)
        events_count = database.count_tunnel_events_for_node(node_id, since_24h)
        
        node_summary = {
            "node_secret_id": node_id,
            "hostname": node.get("public_hostname"),
            "status": node.get("status"),
            "created_at": node.get("created_at"),
            "last_seen_at": node.get("last_seen_at"),
            "cpu_usage": node.get("cpu_usage"),
            "memory_usage": node.get("memory_usage"),
            "active_tunnels": node.get("active_tunnels", 0),
            "total_data_transferred_mb": node.get("total_data_transferred_mb", 0),
            "events_24h": events_count,
            "latest_telemetry": latest_metrics
        }
        nodes_summary.append(node_summary)
    
    return {
        "username": username,
        "total_nodes": len(nodes_summary),
        "nodes": nodes_summary
    } 