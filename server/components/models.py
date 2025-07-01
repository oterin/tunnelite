from os import sep
import time
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
from requests.models import stream_decode_response_unicode
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str
    api_key: str

class Token(BaseModel):
    api_key: str
    token_type: str = "bearer"

class TunnelCreate(BaseModel):
    tunnel_type: str = Field(..., description="the type of tunnel (e.g., http, tcp)")
    local_port: int = Field(..., gt=0, lt=65536, description="the local port to expose")
    ping_data: Optional[dict] = Field(None, description="ping latency data for each node (hostname -> latency_ms)")

class Tunnel(BaseModel):
    public_hostname: str # the public name of the node serving the tunnel
    tunnel_id: str
    owner_username: str
    tunnel_type: str
    local_port: int
    public_url: str
    status: str
    created_at: float

class NodeInfo(BaseModel):
    node_secret_id: str # the private identifier for the node
    public_address: str
    metrics: Optional[dict] = None
    last_seen_at: float = Field(default_factory=time.time)

class NodeInfoPublic(BaseModel):
    public_hostname: str # the public name of the node
    location: str
    public_address: str

class Node(BaseModel):
    node_secret_id: str # the private identifier
    public_hostname: str | None = None # the public name
    status: str = "pending"
    reported_location: str | None = None
    public_address: str | None = None
    verified_ip_address: str | None = None
    verified_geolocation: dict | None = None
    verified_geolocation_verified_at: dict | None = None
    last_seen_at: float | None = None
    # registration fields
    max_clients: int | None = 20
    port_range: str | None = None
    bandwidth_down_mbps: float | None = None
    bandwidth_up_mbps: float | None = None
    node_cert: str | None = None

class ActivationRequest(BaseModel):
    tunnel_id: str
    api_key: str
    node_secret_id: str # the node must identify itself with its secret id

class DeactivationRequest(BaseModel):
    node_secret_id: str

class BanType(str, Enum):
    KICK = "kick"           # immediate disconnect, no persistence
    TEMPBAN = "tempban"     # temporary ban with expiration
    PERMBAN = "permban"     # permanent ban

class BanScope(str, Enum):
    TUNNEL = "tunnel"       # ban from specific tunnel
    NODE = "node"          # ban from specific node
    SERVICE = "service"    # ban from entire service

class BanTarget(str, Enum):
    IP = "ip"              # ban by ip address
    ACCOUNT = "account"    # ban by user account
    BOTH = "both"          # ban both ip and account

class Ban(BaseModel):
    id: str
    ban_type: BanType
    ban_scope: BanScope
    ban_target: BanTarget
    
    # target identifiers
    target_ip: Optional[str] = None
    target_username: Optional[str] = None
    target_user_id: Optional[str] = None
    
    # scope identifiers
    tunnel_id: Optional[str] = None
    node_id: Optional[str] = None
    
    # ban details
    reason: str
    banned_by: str          # admin username who issued the ban
    banned_at: datetime
    expires_at: Optional[datetime] = None  # none for permanent bans
    
    # additional info
    is_active: bool = True
    notes: Optional[str] = None
    
    # tracking
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class BanCheck(BaseModel):
    """result of ban check"""
    is_banned: bool
    ban_type: Optional[BanType] = None
    ban_scope: Optional[BanScope] = None
    reason: Optional[str] = None
    expires_at: Optional[datetime] = None
    banned_by: Optional[str] = None

# --- enums ---
class TunnelType(str, Enum):
    # ... existing code ...
