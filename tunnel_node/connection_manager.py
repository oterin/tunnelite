import asyncio
from fastapi import WebSocket

class Connection:
    """holds state for an active tunnel connection"""
    def __init__(self, websocket: WebSocket, tunnel_id: str, public_hostname: str):
        self.websocket = websocket
        self.tunnel_id = tunnel_id
        self.public_hostname = public_hostname
        # the proxy will put the client's response here
        self.response_queue = asyncio.Queue()

class ConnectionManager:
    def __init__(self):
        self.tunnels_by_id: dict[str, Connection] = {}
        self.tunnels_by_hostname: dict[str, Connection] = {}

    async def connect(self, tunnel_id: str, public_hostname: str, websocket: WebSocket) -> Connection:
        """registers a new active tunnel connection"""
        await websocket.accept()
        connection = Connection(websocket, tunnel_id, public_hostname)
        self.tunnels_by_id[tunnel_id] = connection
        self.tunnels_by_hostname[public_hostname] = connection
        print(f"info:     tunnel activated for {public_hostname}")
        return connection

    def disconnect(self, tunnel_id: str):
        """removes a tunnel when the client disconnects"""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id.pop(tunnel_id)
            if connection.public_hostname in self.tunnels_by_hostname:
                del self.tunnels_by_hostname[connection.public_hostname]
            print(f"info:     tunnel deactivated for {connection.public_hostname}")
            return connection

    async def forward_to_client(self, public_hostname: str, timeout: int = 10) -> bytes:
        """forwards a raw HTTP request from the public internet to the client"""
        if public_hostname in self.tunnels_by_hostname:
            connection = self.tunnels_by_hostname[public_hostname]
            try:
                # wait for the response to be put into the queue
                return await asyncio.wait_for(connection.response_queue.get(), timeout)
            except TimeoutError:
                return b"HTTP/1.1 504 Gateway Timeout\r\n\r\nTunnel Timeout"
        return b"HTTP/1.1 404 Not Found\r\n\r\nTunnel Not Found"

    async def forward_to_proxy(self, tunnel_id: str, data: bytes):
        """forwards a response from the client back to the proxy server via the queue"""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            await connection.response_queue.put(data)

manager = Connectionmanager()
