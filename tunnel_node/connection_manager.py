import asyncio
import time
from typing import Optional
from fastapi import WebSocket

class Connection:
    """holds state for an active tunnel connection."""
    def __init__(self, websocket: WebSocket, tunnel_id: str, public_hostname: str):
        self.websocket = websocket
        self.tunnel_id = tunnel_id
        self.public_hostname = public_hostname
        self.response_queue: asyncio.Queue = asyncio.Queue()
        self.tcp_server_task: Optional[asyncio.Task] = None
        # metrics for this connection
        self.bytes_in: int = 0         # data from public internet -> user client
        self.bytes_out: int = 0        # data from user client -> public internet
        self.connected_at: float = time.time()

class ConnectionManager:
    def __init__(self):
        # main routing tables
        self.tunnels_by_id: dict[str, Connection] = {}
        self.tunnels_by_hostname: dict[str, Connection] = {}

    async def connect(self, tunnel_id: str, public_hostname: str, websocket: WebSocket) -> Connection:
        """registers a new, active tunnel connection."""
        await websocket.accept()
        connection = Connection(websocket, tunnel_id, public_hostname)
        self.tunnels_by_id[tunnel_id] = connection

        # only add http tunnels to the hostname routing table
        if "://" not in public_hostname:
            self.tunnels_by_hostname[public_hostname] = connection

        print(f"info:     tunnel activated for {public_hostname}")
        return connection

    def disconnect(self, tunnel_id: str):
        """removes a tunnel when the client disconnects and cleans up its resources."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id.pop(tunnel_id)
            if connection.public_hostname in self.tunnels_by_hostname:
                del self.tunnels_by_hostname[connection.public_hostname]

            # if this was a tcp tunnel, cancel its server task
            if connection.tcp_server_task:
                connection.tcp_server_task.cancel()

            print(f"info:     tunnel disconnected for {connection.public_hostname}")

    async def forward_to_client(self, tunnel_id: str, data: bytes):
        """forwards raw data from a public connection (http or tcp) to the client."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            # increment bytes_in as data flows into the tunnel from the public
            connection.bytes_in += len(data)
            await connection.websocket.send_bytes(data)

    async def get_http_response_from_client(self, public_hostname: str, timeout: int = 10) -> bytes:
        """waits for a single http response to come back from the client for a specific tunnel."""
        if public_hostname in self.tunnels_by_hostname:
            connection = self.tunnels_by_hostname[public_hostname]
            try:
                # wait for the response to be put into the queue.
                return await asyncio.wait_for(connection.response_queue.get(), timeout)
            except asyncio.TimeoutError:
                return b"HTTP/1.1 504 Gateway Timeout\r\n\r\nTunnel Timeout"
        return b"HTTP/1.1 404 Not Found\r\n\r\nTunnel Not Found"

    def get_connection_by_id(self, tunnel_id: str) -> Optional[Connection]:
        """retrieves an active connection object by its tunnel id."""
        return self.tunnels_by_id.get(tunnel_id)

    def get_connection_by_hostname(self, hostname: str) -> Optional[Connection]:
        """retrieves an active connection object by its public hostname."""
        return self.tunnels_by_hostname.get(hostname)

    async def forward_to_proxy(self, tunnel_id: str, data: bytes):
        """forwards a response from the client back to the proxy server via the queue."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            # increment bytes_out as data flows out of the tunnel to the public
            connection.bytes_out += len(data)
            await connection.response_queue.put(data)

    async def close_tunnel(self, tunnel_id: str) -> bool:
        """closes a tunnel connection and cleans up its resources."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            try:
                # close the websocket connection if it's still open
                if not connection.websocket.client_state.DISCONNECTED:
                    await connection.websocket.close(code=1000, reason="tunnel closed by server")
            except Exception as e:
                print(f"error:    failed to close websocket for tunnel {tunnel_id}: {e}")
            
            # clean up the connection
            self.disconnect(tunnel_id)
            return True
        return False

    def get_and_reset_metrics(self) -> dict:
        """collects metrics from all active tunnels and resets their counters."""
        metrics_report = {
            "total_active_tunnels": len(self.tunnels_by_id),
            "tunnels": []
        }
        for tunnel_id, connection in self.tunnels_by_id.items():
            metrics_report["tunnels"].append({
                "tunnel_id": tunnel_id,
                "bytes_in": connection.bytes_in,
                "bytes_out": connection.bytes_out,
                "connected_at": connection.connected_at,
            })
            # reset counters for the next interval
            connection.bytes_in = 0
            connection.bytes_out = 0

        return metrics_report

# create a single, shared instance for the application.
manager = ConnectionManager()
