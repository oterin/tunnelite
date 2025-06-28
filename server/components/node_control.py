import asyncio
import json
import os
import subprocess
import tempfile
import time
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

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, api_key: str):
    """WebSocket endpoint for nodes to connect to the control plane"""
    node = database.get_node_by_secret_id(api_key)
    if not node:
        await websocket.close(code=1008, reason="Invalid API key")
        return

    node_secret_id = node["node_secret_id"]
    await node_manager.connect(websocket, node_secret_id)
    
    try:
        while True:
            try:
                # Wait for a message with a timeout for heartbeat mechanism
                data = await asyncio.wait_for(websocket.receive_json(), timeout=60)
                
                message_type = data.get("type")
                
                if message_type == "heartbeat":
                    database.update_node_last_seen(node_secret_id)
                    await node_manager.send_message_to_node(node_secret_id, {"type": "heartbeat_ack"})
                
                elif message_type == "tunnel_status_update":
                    # Node is reporting status of a tunnel
                    tunnel_id = data.get("tunnel_id")
                    status = data.get("status")
                    if tunnel_id and status:
                        database.update_tunnel_status(tunnel_id, status)
                        print(f"info:     tunnel {tunnel_id[:8]} status updated to {status}")
                
                elif message_type == "metrics_update":
                    # Node is reporting system metrics
                    metrics = data.get("metrics", {})
                    database.update_node_metrics(node_secret_id, metrics)
                
                elif message_type == "error_report":
                    # Node is reporting an error
                    error_msg = data.get("error", "Unknown error")
                    tunnel_id = data.get("tunnel_id")
                    print(f"error:    node {node_secret_id[:8]} reported error: {error_msg}")
                    if tunnel_id:
                        database.update_tunnel_status(tunnel_id, "error")
                
                else:
                    print(f"warning:  unknown message type from node {node_secret_id[:8]}: {message_type}")
                    
            except asyncio.TimeoutError:
                # No message received, send a heartbeat to check if client is alive
                print(f"debug:    sending heartbeat to node {node_secret_id[:8]}")
                await node_manager.send_message_to_node(node_secret_id, {"type": "heartbeat"})

    except WebSocketDisconnect:
        node_manager.disconnect(node_secret_id)
    except Exception as e:
        print(f"error:    unexpected error in control channel for node {node_secret_id[:8]}: {e}")
        node_manager.disconnect(node_secret_id)

@router.post("/ddns-update")
async def update_node_ip(
    request: Request,
    node: dict = Depends(get_node_from_api_key)
):
    """
    Endpoint for tunnel nodes to update their public IP address.
    The server will then update the corresponding A record in DNS.
    """
    try:
        payload = await request.json()
        ip_address = payload.get("ip_address")
        if not ip_address:
            raise HTTPException(status_code=400, detail="ip_address is required.")

        hostname = node.get("public_hostname")
        if not hostname:
             raise HTTPException(status_code=400, detail="Node has no public_hostname.")

        success = dns.update_node_a_record(hostname, ip_address)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update DNS record via provider.")

        # Also update the IP in our own database for record-keeping
        node_secret_id = node["node_secret_id"]
        port = node.get("port", 443)
        updated_public_address = f"https://{hostname}:{port}"
        
        # Update the node record with the new public address
        node_update = {
            "node_secret_id": node_secret_id,
            "public_address": updated_public_address,
            "verified_ip_address": ip_address
        }
        database.upsert_node(node_update)

        return {"status": "success", "hostname": hostname, "ip_address": ip_address}

    except Exception as e:
        # To avoid leaking internal error details, log the actual error and return a generic message
        print(f"error:    DDNS update failed for node {node.get('node_secret_id', 'unknown')}: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during DDNS update.")

@router.post("/tunnel/activate")
async def activate_tunnel(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint to manually activate a tunnel on its assigned node.
    Typically called by the tunnel creation process.
    """
    try:
        payload = await request.json()
        tunnel_id = payload.get("tunnel_id")
        
        if not tunnel_id:
            raise HTTPException(status_code=400, detail="tunnel_id is required.")
        
        # Get the tunnel details
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="Tunnel not found.")
        
        # Check if user owns this tunnel
        if tunnel.get("owner_username") != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Not authorized to activate this tunnel.")
        
        node_secret_id = tunnel.get("node_secret_id")
        if not node_secret_id:
            raise HTTPException(status_code=400, detail="Tunnel has no assigned node.")
        
        # Check if node is online
        if not node_manager.is_node_online(node_secret_id):
            raise HTTPException(status_code=503, detail="Assigned node is offline.")
        
        # Send activation command to node
        success = await node_manager.activate_tunnel_on_node(node_secret_id, tunnel)
        
        if success:
            database.update_tunnel_status(tunnel_id, "activating")
            return {"status": "success", "message": "Tunnel activation command sent to node."}
        else:
            raise HTTPException(status_code=500, detail="Failed to send activation command to node.")
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"error:    tunnel activation failed: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during tunnel activation.")

@router.delete("/tunnel/{tunnel_id}")
async def deactivate_tunnel(
    tunnel_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Endpoint to deactivate a tunnel on its assigned node.
    """
    try:
        # Get the tunnel details
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="Tunnel not found.")
        
        # Check if user owns this tunnel
        if tunnel.get("owner_username") != current_user.get("username"):
            raise HTTPException(status_code=403, detail="Not authorized to deactivate this tunnel.")
        
        node_secret_id = tunnel.get("node_secret_id")
        if not node_secret_id:
            # Tunnel has no assigned node, just mark as deleted
            database.update_tunnel_status(tunnel_id, "deleted")
            return {"status": "success", "message": "Tunnel marked as deleted."}
        
        # Send deactivation command to node (if online)
        if node_manager.is_node_online(node_secret_id):
            await node_manager.deactivate_tunnel_on_node(node_secret_id, tunnel_id)
        
        # Mark tunnel as deleted in database
        database.update_tunnel_status(tunnel_id, "deleted")
        
        return {"status": "success", "message": "Tunnel deactivated and deleted."}
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"error:    tunnel deactivation failed: {e}")
        raise HTTPException(status_code=500, detail="An internal error occurred during tunnel deactivation.")

@router.get("/nodes/status")
async def get_nodes_status(current_user: dict = Depends(get_current_user)):
    """
    Get status of all nodes (admin endpoint)
    """
    # This could be restricted to admin users only
    nodes = database.get_all_nodes()
    
    node_status = []
    for node in nodes:
        node_secret_id = node["node_secret_id"]
        status = {
            "node_id": node_secret_id[:8],  # Only show first 8 chars for security
            "hostname": node.get("public_hostname"),
            "status": "online" if node_manager.is_node_online(node_secret_id) else "offline",
            "active_tunnels": len(node_manager.get_node_tunnels(node_secret_id)),
            "last_seen": node.get("last_seen"),
            "metrics": node.get("metrics", {})
        }
        node_status.append(status)
    
    return {"nodes": node_status}

@router.get("/tunnels/active")
async def get_active_tunnels(current_user: dict = Depends(get_current_user)):
    """
    Get all currently active tunnels across all nodes
    """
    active_tunnels = []
    
    for node_secret_id, tunnels in node_manager.node_tunnels.items():
        node = database.get_node_by_secret_id(node_secret_id)
        node_hostname = node.get("public_hostname", "unknown") if node else "unknown"
        
        for tunnel_id, tunnel_data in tunnels.items():
            active_tunnels.append({
                "tunnel_id": tunnel_id[:8],  # Truncate for security
                "tunnel_type": tunnel_data.get("tunnel_type"),
                "public_url": tunnel_data.get("public_url"),
                "node_hostname": node_hostname,
                "owner": tunnel_data.get("owner_username")
            })
    
    return {"active_tunnels": active_tunnels}

@router.post("/generate-ssl-certificate")
async def generate_ssl_certificate(
    request: Request,
    node: dict = Depends(get_node_from_api_key)
):
    """
    Server-side SSL certificate generation for nodes.
    This endpoint generates SSL certificates using DNS challenges without exposing
    the Cloudflare API credentials to the nodes.
    """
    try:
        payload = await request.json()
        public_ip = payload.get("public_ip")
        
        if not public_ip:
            raise HTTPException(status_code=400, detail="public_ip is required")
        
        node_secret_id = node["node_secret_id"]
        hostname = node.get("public_hostname")
        
        if not hostname:
            raise HTTPException(status_code=400, detail="Node has no public_hostname")
        
        # update dns record first
        print(f"info:     Updating DNS record for {hostname} to {public_ip}")
        dns_success = dns.update_node_a_record(hostname, public_ip)
        
        if not dns_success:
            raise HTTPException(status_code=500, detail="Failed to update DNS record")
        
        # wait for dns propagation
        print(f"info:     Waiting for DNS propagation for {hostname}")
        if not await wait_for_dns_propagation(hostname, public_ip):
            raise HTTPException(status_code=500, detail="DNS propagation failed")
        
        # generate ssl certificate using dns challenge
        print(f"info:     Generating SSL certificate for {hostname}")
        cert_data = await generate_certificate_with_dns_challenge(hostname)
        
        if not cert_data:
            raise HTTPException(status_code=500, detail="SSL certificate generation failed")
        
        # update node record with certificate info
        node_update = {
            "node_secret_id": node_secret_id,
            "public_address": f"https://{hostname}:443",
            "verified_ip_address": public_ip,
            "ssl_cert_generated_at": time.time()
        }
        database.upsert_node(node_update)
        
        return {
            "status": "success",
            "hostname": hostname,
            "ssl_certificate": cert_data["certificate"],
            "ssl_private_key": cert_data["private_key"],
            "certificate_path": f"/etc/letsencrypt/live/{hostname}/fullchain.pem",
            "private_key_path": f"/etc/letsencrypt/live/{hostname}/privkey.pem"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"error:    SSL certificate generation failed for node {node.get('node_secret_id', 'unknown')}: {e}")
        raise HTTPException(status_code=500, detail="SSL certificate generation failed")

async def wait_for_dns_propagation(hostname: str, expected_ip: str, max_attempts: int = 30) -> bool:
    """
    Wait for DNS propagation to complete by checking if the hostname resolves to the expected IP.
    """
    import socket as socket_module
    
    print(f"info:     Waiting for DNS propagation: {hostname} -> {expected_ip}")
    
    for attempt in range(max_attempts):
        try:
            resolved_ip = socket_module.gethostbyname(hostname)
            if resolved_ip == expected_ip:
                print(f"info:     DNS propagation successful: {hostname} -> {resolved_ip}")
                return True
            else:
                print(f"debug:    DNS not yet propagated: {hostname} -> {resolved_ip} (expected {expected_ip})")
        except socket_module.gaierror as e:
            print(f"debug:    DNS resolution failed for {hostname}: {e}")
        
        if attempt < max_attempts - 1:  # don't sleep on the last attempt
            await asyncio.sleep(10)  # wait 10 seconds between attempts
    
    print(f"error:    DNS propagation failed after {max_attempts} attempts")
    return False

async def generate_certificate_with_dns_challenge(hostname: str) -> Dict[str, str]:
    """
    Generate SSL certificate using DNS challenge via Cloudflare.
    Returns dictionary with certificate and private key content.
    """
    # create temporary credentials file
    creds_file = None
    try:
        # import cloudflare credentials from dns component
        from .dns import CLOUDFLARE_API_TOKEN
        if not CLOUDFLARE_API_TOKEN:
            print("error:    Cloudflare API token not available")
            return None
        
        # create temporary credentials file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ini', delete=False) as f:
            f.write(f"dns_cloudflare_api_token = {CLOUDFLARE_API_TOKEN}\n")
            creds_file = f.name
        
        # set restrictive permissions
        os.chmod(creds_file, 0o600)
        
        # check if certbot-dns-cloudflare plugin is installed
        try:
            result = subprocess.run(["certbot", "plugins"], capture_output=True, text=True)
            if "dns-cloudflare" not in result.stdout:
                print("info:     Installing certbot-dns-cloudflare plugin...")
                subprocess.run(["pip", "install", "certbot-dns-cloudflare"], check=True)
        except Exception as e:
            print(f"warn:     Could not check/install certbot plugin: {e}")
        
        # run certbot with dns challenge
        command = [
            "certbot", "certonly",
            "--dns-cloudflare",
            "--dns-cloudflare-credentials", creds_file,
            "--dns-cloudflare-propagation-seconds", "60",
            "-d", hostname,
            "--agree-tos",
            "-n",  # non-interactive
            "-m", f"admin@{hostname.split('.', 1)[1]}",  # use domain admin email
            "--no-eff-email",
            "--cert-name", hostname,
            "--verbose"
        ]
        
        print(f"info:     Running certbot: {' '.join(command)}")
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        
        if result.stdout:
            print(f"debug:    Certbot output: {result.stdout}")
        
        # read generated certificate files
        cert_path = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"
        key_path = f"/etc/letsencrypt/live/{hostname}/privkey.pem"
        
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            print(f"error:    Certificate files not found after certbot run")
            return None
        
        # read certificate content
        with open(cert_path, 'r') as f:
            certificate_content = f.read()
        
        with open(key_path, 'r') as f:
            private_key_content = f.read()
        
        print(f"info:     SSL certificate generated successfully for {hostname}")
        return {
            "certificate": certificate_content,
            "private_key": private_key_content
        }
        
    except subprocess.CalledProcessError as e:
        print(f"error:    Certbot failed: {e}")
        if e.stdout:
            print(f"Certbot stdout: {e.stdout}")
        if e.stderr:
            print(f"Certbot stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"error:    Certificate generation failed: {e}")
        return None
    finally:
        # clean up credentials file
        if creds_file and os.path.exists(creds_file):
            try:
                os.remove(creds_file)
                print("info:     Cleaned up temporary credentials file")
            except Exception as e:
                print(f"warn:     Could not clean up credentials file: {e}")