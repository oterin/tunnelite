import asyncio
import secrets
import time
from typing import Optional, Tuple
from fastapi import WebSocket

class Connection:
    """holds state for an active tunnel connection."""
    def __init__(self, websocket: WebSocket, tunnel_id: str, public_hostname: str):
        self.websocket = websocket
        self.tunnel_id = tunnel_id
        self.public_hostname = public_hostname
        # http tunnels are request/response, so one queue is fine.
        self.http_response_queue: asyncio.Queue = asyncio.Queue()
        # tcp tunnels can have many concurrent connections. we need a queue for each.
        self.tcp_response_queues: dict[str, asyncio.Queue] = {}
        self.tcp_server_task: Optional[asyncio.Task] = None
        # metrics for this connection
        self.bytes_in: int = 0         # data from public internet -> user client
        self.bytes_out: int = 0        # data from user client -> public internet
        self.packets_in: int = 0       # packet count in
        self.packets_out: int = 0      # packet count out
        self.connected_at: float = time.time()
        self.last_activity: float = time.time()

class ConnectionManager:
    def __init__(self):
        # main routing tables
        self.tunnels_by_id: dict[str, Connection] = {}
        self.tunnels_by_hostname: dict[str, Connection] = {}

    async def connect(self, tunnel_id: str, public_hostname: str, websocket: WebSocket) -> Connection:
        """registers a new, active tunnel connection."""
        # websocket should already be accepted by the calling endpoint
        connection = Connection(websocket, tunnel_id, public_hostname)
        self.tunnels_by_id[tunnel_id] = connection

        # only add http tunnels to the hostname routing table
        if "://" not in public_hostname:
            self.tunnels_by_hostname[public_hostname] = connection

        print(f"info:     tunnel activated for {public_hostname} (id: {tunnel_id[:8]})")
        return connection

    def disconnect(self, tunnel_id: str):
        """removes a tunnel when the client disconnects and cleans up its resources."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id.pop(tunnel_id)
            if connection.public_hostname in self.tunnels_by_hostname:
                del self.tunnels_by_hostname[connection.public_hostname]

            # if this was a tcp tunnel, cancel its server task immediately
            if connection.tcp_server_task and not connection.tcp_server_task.done():
                connection.tcp_server_task.cancel()
                print(f"info:     cancelled tcp server task for tunnel {tunnel_id[:8]}")

            # calculate session stats
            duration = time.time() - connection.connected_at
            print(f"info:     tunnel disconnected for {connection.public_hostname}: "
                  f"duration={duration:.1f}s, "
                  f"packets_in={connection.packets_in}, packets_out={connection.packets_out}, "
                  f"bytes_in={connection.bytes_in}, bytes_out={connection.bytes_out}")

    def register_tcp_sub_connection(self, tunnel_id: str) -> Optional[Tuple[str, asyncio.Queue]]:
        """creates a new response queue for a concurrent tcp connection."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            sub_connection_id = secrets.token_hex(4)
            queue = asyncio.Queue()
            connection.tcp_response_queues[sub_connection_id] = queue
            return sub_connection_id, queue
        return None

    def unregister_tcp_sub_connection(self, tunnel_id: str, sub_connection_id: str):
        """removes the response queue for a closed tcp connection."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            connection.tcp_response_queues.pop(sub_connection_id, None)

    async def send_control_message_to_client(self, tunnel_id: str, sub_connection_id: str, frame_type: bytes):
        """sends a control frame (e.g., close) to the client for a specific sub-connection."""
        if tunnel_id in self.tunnels_by_id:
            try:
                connection = self.tunnels_by_id[tunnel_id]
                id_bytes = sub_connection_id.encode('utf-8')
                id_len = len(id_bytes)
                payload = frame_type + id_len.to_bytes(1, 'big') + id_bytes
                await connection.websocket.send_bytes(payload)
            except Exception:
                # client likely disconnected, safe to ignore
                pass

    async def forward_to_client(self, tunnel_id: str, data: bytes, sub_connection_id: Optional[str] = None):
        """forwards raw data from a public connection (http or tcp) to the client."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            connection.last_activity = time.time()
            
            payload = data
            # for tcp, we frame the data with the sub-connection id
            if sub_connection_id:
                # [type (1 byte)] + [id_len (1 byte)] + [id] + [data]
                id_bytes = sub_connection_id.encode('utf-8')
                id_len = len(id_bytes)
                payload = b'T' + id_len.to_bytes(1, 'big') + id_bytes + data
            else: # for http, we just mark it as http data
                payload = b'H' + data

            connection.bytes_in += len(payload)
            connection.packets_in += 1
            await connection.websocket.send_bytes(payload)

    async def get_http_response_from_client(self, public_hostname: str, timeout: int = 10) -> bytes:
        """waits for a single http response to come back from the client for a specific tunnel."""
        if public_hostname in self.tunnels_by_hostname:
            connection = self.tunnels_by_hostname[public_hostname]
            try:
                # wait for the response to be put into the queue.
                return await asyncio.wait_for(connection.http_response_queue.get(), timeout)
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
        """forwards a response from the client back to the correct proxy server queue."""
        if tunnel_id not in self.tunnels_by_id:
            return
            
        connection = self.tunnels_by_id[tunnel_id]
        connection.last_activity = time.time()
        connection.bytes_out += len(data)
        connection.packets_out += 1

        data_type = data[0:1]
        
        if data_type == b'H':
            # http data goes to the single http queue
            await connection.http_response_queue.put(data[1:])
        elif data_type == b'T':
            # tcp data is demultiplexed to the correct sub-connection queue
            try:
                id_len = int.from_bytes(data[1:2], 'big')
                sub_connection_id = data[2:2+id_len].decode('utf-8')
                payload = data[2+id_len:]
                
                if sub_connection_id in connection.tcp_response_queues:
                    await connection.tcp_response_queues[sub_connection_id].put(payload)
                else:
                    # this can happen if the tcp connection was already closed by the node
                    # but the client sent a final packet. it's safe to ignore.
                    pass
            except (IndexError, UnicodeDecodeError):
                print(f"error:    could not parse client tcp frame for tunnel {tunnel_id[:8]}")
        elif data_type == b'C': # Close frame from client
            try:
                id_len = int.from_bytes(data[1:2], 'big')
                sub_connection_id = data[2:2+id_len].decode('utf-8')
                if sub_connection_id in connection.tcp_response_queues:
                    # a None in the queue is the signal to close the connection.
                    await connection.tcp_response_queues[sub_connection_id].put(None)
            except (IndexError, UnicodeDecodeError):
                print(f"error:    could not parse client close frame for tunnel {tunnel_id[:8]}")

    async def close_tunnel(self, tunnel_id: str) -> bool:
        """closes a tunnel connection and cleans up its resources immediately."""
        if tunnel_id in self.tunnels_by_id:
            connection = self.tunnels_by_id[tunnel_id]
            try:
                # close the websocket connection if it's still open
                if not connection.websocket.client_state.DISCONNECTED:
                    await connection.websocket.close(code=1000, reason="tunnel closed by server")
                    print(f"info:     forcibly closed websocket for tunnel {tunnel_id[:8]}")
            except Exception as e:
                print(f"error:    failed to close websocket for tunnel {tunnel_id}: {e}")
            
            # clean up the connection immediately
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
            uptime = time.time() - connection.connected_at
            idle_time = time.time() - connection.last_activity
            
            metrics_report["tunnels"].append({
                "tunnel_id": tunnel_id,
                "public_hostname": connection.public_hostname,
                "bytes_in": connection.bytes_in,
                "bytes_out": connection.bytes_out,
                "packets_in": connection.packets_in,
                "packets_out": connection.packets_out,
                "connected_at": connection.connected_at,
                "uptime_seconds": uptime,
                "idle_seconds": idle_time,
            })
            # reset counters for the next interval
            connection.bytes_in = 0
            connection.bytes_out = 0
            connection.packets_in = 0
            connection.packets_out = 0

        return metrics_report

    def cleanup_stale_connections(self, max_idle_seconds: int = 300):
        """cleanup connections that have been idle for too long"""
        current_time = time.time()
        stale_tunnels = []
        
        for tunnel_id, connection in self.tunnels_by_id.items():
            idle_time = current_time - connection.last_activity
            if idle_time > max_idle_seconds:
                stale_tunnels.append(tunnel_id)
        
        for tunnel_id in stale_tunnels:
            print(f"info:     cleaning up stale tunnel {tunnel_id[:8]} (idle for {idle_time:.1f}s)")
            asyncio.create_task(self.close_tunnel(tunnel_id))

# create a single, shared instance for the application.
manager = ConnectionManager()
