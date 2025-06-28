import time
import asyncio
import json
from typing import Dict, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Depends, HTTPException
from server.components import database
from server.components.auth import get_current_user, get_node_from_api_key
from server.components import dns

router = APIRouter(prefix="/internal/control", tags=["internal-control"])

class NodeConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.node_tunnels: Dict[str, Dict[str, any]] = {}  # node_id -> {tunnel_id: tunnel_data}

    async def connect(self, websocket: WebSocket, node_secret_id: str):
        await websocket.accept()
        self.active_connections[node_secret_id] = websocket
        database.update_node_status(node_secret_id, "active")
        print(f"info:     node {node_secret_id[:8]} connected to control channel.")

    def disconnect(self, node_secret_id: str):
        if node_secret_id in self.active_connections:
            del self.active_connections[node_secret_id]
        if node_secret_id in self.node_tunnels:
            del self.node_tunnels[node_secret_id]
        database.update_node_status(node_secret_id, "offline")
        print(f"info:     node {node_secret_id[:8]} disconnected from control channel.")

    async def send_message_to_node(self, node_secret_id: str, message: dict):
        if node_secret_id in self.active_connections:
            websocket = self.active_connections[node_secret_id]
            try:
                await websocket.send_json(message)
                return True
            except Exception as e:
                print(f"error:    could not send message to node {node_secret_id[:8]}: {e}")
                self.disconnect(node_secret_id)
                return False
        return False

    async def activate_tunnel_on_node(self, node_secret_id: str, tunnel_data: dict):
        """Send tunnel activation command to a specific node"""
        message = {
            "type": "activate_tunnel",
            "tunnel_id": tunnel_data["tunnel_id"],
            "tunnel_type": tunnel_data["tunnel_type"],
            "local_port": tunnel_data.get("local_port"),
            "public_url": tunnel_data["public_url"]
        }
        
        success = await self.send_message_to_node(node_secret_id, message)
        if success:
            # Track this tunnel on this node
            if node_secret_id not in self.node_tunnels:
                self.node_tunnels[node_secret_id] = {}
            self.node_tunnels[node_secret_id][tunnel_data["tunnel_id"]] = tunnel_data
            print(f"info:     activated tunnel {tunnel_data['tunnel_id'][:8]} on node {node_secret_id[:8]}")
        
        return success

    async def deactivate_tunnel_on_node(self, node_secret_id: str, tunnel_id: str):
        """Send tunnel deactivation command to a specific node"""
        message = {
            "type": "deactivate_tunnel",
            "tunnel_id": tunnel_id
        }
        
        success = await self.send_message_to_node(node_secret_id, message)
        if success:
            # Remove from tracking
            if node_secret_id in self.node_tunnels and tunnel_id in self.node_tunnels[node_secret_id]:
                del self.node_tunnels[node_secret_id][tunnel_id]
            print(f"info:     deactivated tunnel {tunnel_id[:8]} on node {node_secret_id[:8]}")
        
        return success

    def get_node_tunnels(self, node_secret_id: str) -> Dict[str, any]:
        """Get all tunnels currently active on a specific node"""
        return self.node_tunnels.get(node_secret_id, {})

    def is_node_online(self, node_secret_id: str) -> bool:
        """Check if a node is currently connected"""
        return node_secret_id in self.active_connections

node_manager = NodeConnectionManager()