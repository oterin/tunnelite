from os import sep
import time
from pydantic import BaseModel, Field
from typing import Optional
from requests.models import stream_decode_response_unicode

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
