from os import sep
from pydantic import BaseModel, Field

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
