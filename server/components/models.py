from os import sep
import time
from pydantic import BaseModel, Field
from requests.models import stream_decode_response_unicode

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    api_key: str
    token_type: str = "bearer"

class TunnelCreate(BaseModel):
    tunnel_type: str = Field(..., description="the type of tunnel (e.g., http, tcp)")
    local_port: int = Field(..., gt=0, lt=65536, description="the local port to expose")
    preferred_node_id: str = Field(..., description="the id of the node selected by the client")

class Tunnel(BaseModel):
    node_id: str
    tunnel_id: str
    owner_username: str
    tunnel_type: str
    local_port: int
    public_url: str
    status: str
    created_at: float

class NodeInfo(BaseModel):
    node_id: str
    location: str
    last_seen_at: float = Field(default_factory=time.time)

class NodeInfoPublic(BaseModel):
    node_id: str
    location: str
    public_address: str

class Node(BaseModel):
    node_id: str
    status: str
    reported_location: str | None = None
    public_address: str | None = None
    verified_ip_address: str | None = None
    verified_geolocation: str | None = None
    verified_geolocation_verified_at: dict | None = None
    last_seen_at: float | None = None
