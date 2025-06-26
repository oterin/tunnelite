import anyio
from fastapi import APIRouter, Request, Response, HTTPException, status
from .connection_manager import manager

# a new router for the proxy logic.
# it has no prefix, so its routes are at the root of the app.
proxy_router = APIRouter()

# --- http/s reverse proxy logic ---

@proxy_router.api_route("/{full_path:path}", include_in_schema=False, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def http_proxy_catch_all(request: Request, full_path: str):
    """
    this catch-all route acts as the http/s reverse proxy.
    it intercepts any request that doesn't match a defined api route (e.g., /internal/health).
    """
    # 1. get the hostname from the host header.
    host_header = request.headers.get("host")
    if not host_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="host header is missing."
        )

    # 2. security check: ensure this node is authoritative for the hostname.
    connection = manager.get_connection_by_hostname(host_header)
    if not connection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"tunnel for {host_header} not found or not active on this node."
        )

    # 3. reconstruct the raw http request to forward to the client.
    # start with the request line (e.g., get /path http/1.1)
    request_line = f"{request.method} /{full_path or ''} HTTP/{request.scope['http_version']}"

    # format headers, including the original host header.
    headers = [f"{name.decode('utf-8')}: {value.decode('utf-8')}" for name, value in request.headers.raw]

    # combine into a raw request string
    raw_headers = "\r\n".join([request_line] + headers)

    # encode headers and add the body
    raw_request = f"{raw_headers}\r\n\r\n".encode('utf-8')
    raw_request += await request.body()

    # 4. forward the reconstructed request to the correct client.
    await manager.forward_to_client(connection.tunnel_id, raw_request)

    # 5. wait for the response to come back from the client's dedicated queue.
    raw_response = await manager.get_http_response_from_client(host_header)

    # 6. parse the raw response from the client and return it.
    try:
        # separate headers from the body
        header_bytes, body_bytes = raw_response.split(b'\r\n\r\n', 1)
        header_lines = header_bytes.decode('utf-8').split('\r\n')

        # parse the status line
        status_line = header_lines.pop(0)
        status_code = int(status_line.split(' ')[1])

        # parse headers into a dictionary
        response_headers = {
            name.strip(): value.strip()
            for name, value in (line.split(':', 1) for line in header_lines)
        }

        # these headers are managed by the server, so we remove them
        # to avoid conflicts with what fastapi/uvicorn will add.
        response_headers.pop("content-length", None)
        response_headers.pop("transfer-encoding", None)
        response_headers.pop("connection", None)

        return Response(content=body_bytes, status_code=status_code, headers=response_headers)
    except Exception as e:
        print(f"error: could not parse client response: {e}")
        return Response(content=b"bad gateway", status_code=502)

# --- tcp/udp proxy logic (still needed for non-http tunnels) ---

async def tcp_proxy_handler(client_stream: anyio.abc.SocketStream, tunnel_id: str):
    """handles a single public tcp connection and proxies data in both directions."""
    print(f"info:     new tcp connection for tunnel {tunnel_id}")
    try:
        async with anyio.create_task_group() as tg:
            async def public_to_ws():
                while True:
                    data = await client_stream.receive(4096)
                    if not data: break
                    await manager.forward_to_client(tunnel_id, data)
                tg.cancel_scope.cancel()

            async def ws_to_public():
                connection = manager.get_connection_by_id(tunnel_id)
                if not connection:
                    tg.cancel_scope.cancel()
                    return

                while True:
                    response_data = await connection.response_queue.get()
                    if response_data is None: break
                    await client_stream.send(response_data)
                tg.cancel_scope.cancel()

            tg.start_soon(public_to_ws)
            tg.start_soon(ws_to_public)
    except Exception as e:
        print(f"error:    tcp proxy handler for {tunnel_id} failed: {e}")
    finally:
        print(f"info:     closing tcp connection for tunnel {tunnel_id}")
        await client_stream.aclose()

async def start_tcp_listener(tunnel_id: str, port: int):
    """starts a dedicated tcp listener for a single tunnel on a specific port."""
    try:
        listener = await anyio.create_tcp_listener(local_port=port)
        print(f"info:     tcp listener started for tunnel {tunnel_id} on port {port}")
        handler = lambda client: tcp_proxy_handler(client, tunnel_id)
        await listener.serve(handler)
    except Exception as e:
        print(f"error:    could not start tcp listener on port {port}: {e}")
