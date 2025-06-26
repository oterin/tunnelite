from ast import Return
import anyio
from .connection_manager import ConnectionManager

# the port the internal http proxy will listen on.
# in production, an external load balancer will forward public port 80/443 traffic to this port.
PROXY_PORT = 8080

async def http_proxy_handler(client_stream: anyio.abc.SocketStream, manager: ConnectionManager, is_secure: bool = False):
    """handles a single public http request from start to finish."""
    hostname = ""
    try:
        # 1. read the incoming request and parse the host header
        request_data = await client_stream.receive(4096)
        if not request_data:
            return

        headers = request_data.decode('utf-8', errors='ignore').split('\r\n')
        for header in headers:
            if header.lower().startswith('host:'):
                hostname = header.split(':', 1)[1].strip()
                break

        if not hostname:
            await client_stream.send(b"http/1.1 400 bad request\r\n\r\nhost header is missing.")
            return

        # 2. security check: ensure this node is authoritative for the hostname
        if hostname not in manager.tunnels_by_hostname:
            await client_stream.send(b"http/1.1 404 not found\r\n\r\ntunnel not found.")
            return

        # 3. add x-forwarded-proto header if the connection is secure
        if is_secure:
            # this is a simplified way to inject a header. a real implementation
            # would parse the http request more robustly.
            request_lines = request_data.split(b'\r\n')
            request_lines.insert(1, b'x-forwarded-proto: https')
            request_data = b'\r\n'.join(request_lines)

        # 4. forward the request to the correct client via the connection manager
        await manager.forward_to_client(manager.tunnels_by_hostname[hostname].tunnel_id, request_data)

        # 4. wait for the response to come back from the client
        response_data = await manager.get_http_response_from_client(hostname)

        # 6. write the client's response back to the original requester
        await client_stream.send(response_data)

    except Exception as e:
        print(f"error:    proxy handler failed for {hostname}: {e}")
    finally:
        await client_stream.aclose()


async def tcp_proxy_handler(client_stream: anyio.abc.SocketStream, manager: ConnectionManager, tunnel_id: str):
    """handles a single public tcp connection and proxies data in both directions."""
    print(f"info:     new tcp connection for tunnel {tunnel_id}")
    try:
        async with anyio.create_task_group() as tg:
            # task 1: read from public client -> forward to websocket
            async def public_to_ws():
                while True:
                    data = await client_stream.receive(4096)
                    if not data:
                        break
                    await manager.forward_to_client(tunnel_id, data)
                tg.cancel_scope.cancel()

            # task 2: read from websocket -> forward to public client
            async def ws_to_public():
                # get the connection object to access its dedicated response queue
                connection = manager.get_connection_by_id(tunnel_id)
                if not connection:
                    tg.cancel_scope.cancel()
                    return

                while True:
                    # wait for the client to send data back up for this tunnel
                    response_data = await connection.response_queue.get()
                    if response_data is None: # use none as a signal to close
                        break
                    await client_stream.send(response_data)
                tg.cancel_scope.cancel()

            tg.start_soon(public_to_ws)
            tg.start_soon(ws_to_public)

    except Exception as e:
        print(f"error:    tcp proxy handler for {tunnel_id} failed: {e}")
    finally:
        print(f"info:     closing tcp connection for tunnel {tunnel_id}")
        await client_stream.aclose()


async def start_tcp_listener(manager: ConnectionManager, tunnel_id: str, port: int):
    """starts a dedicated tcp listener for a single tunnel on a specific port."""
    try:
        listener = await anyio.create_tcp_listener(local_port=port)
        print(f"info:     tcp listener started for tunnel {tunnel_id} on port {port}")
        handler = lambda client: tcp_proxy_handler(client, manager, tunnel_id)
        await listener.serve(handler)
    except Exception as e:
        # this can happen if the port is already in use, which is a critical failure.
        print(f"error:    could not start tcp listener on port {port}: {e}")


async def run_http_proxy_server(manager: ConnectionManager):
    """starts the main http proxy server on a single internal port."""
    listener = await anyio.create_tcp_listener(local_port=PROXY_PORT)
    print(f"info:     http proxy server listening on 127.0.0.1:{PROXY_PORT}")
    handler = lambda client: http_proxy_handler(client, manager)
    await listener.serve(handler)
