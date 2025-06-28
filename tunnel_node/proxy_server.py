import anyio
import time
from fastapi import APIRouter, Request, Response, HTTPException, status
from .connection_manager import manager
from .network_logger import NetworkEvent, NetworkEventType, network_logger
import asyncio

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
        # log error event
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.ERROR,
            client_ip=request.client.host,
            method=request.method,
            path=f"/{full_path}",
            error_message=f"tunnel for {host_header} not found",
            metadata={"host_header": host_header}
        ))
        
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
    request_body = await request.body()
    raw_request += request_body

    # log incoming http request
    network_logger.log_event(NetworkEvent(
        timestamp=time.time(),
        event_type=NetworkEventType.HTTP_REQUEST,
        tunnel_id=connection.tunnel_id,
        client_ip=request.client.host,
        method=request.method,
        path=f"/{full_path}",
        bytes_transferred=len(raw_request),
        direction="in",
        protocol="http"
    ))

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

        # log outgoing http response
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.HTTP_RESPONSE,
            tunnel_id=connection.tunnel_id,
            client_ip=request.client.host,
            method=request.method,
            path=f"/{full_path}",
            status_code=status_code,
            bytes_transferred=len(raw_response),
            direction="out",
            protocol="http"
        ))

        return Response(content=body_bytes, status_code=status_code, headers=response_headers)
    except Exception as e:
        # log parsing error
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.ERROR,
            tunnel_id=connection.tunnel_id,
            client_ip=request.client.host,
            error_message=f"failed to parse client response: {e}",
            metadata={"raw_response_length": len(raw_response)}
        ))
        
        print(f"error: could not parse client response: {e}")
        return Response(content=b"bad gateway", status_code=502)

# --- tcp/udp proxy logic (still needed for non-http tunnels) ---

async def tcp_proxy_handler(client_stream: anyio.abc.SocketStream, tunnel_id: str):
    """handles a single public tcp connection and proxies data in both directions."""
    client_addr, client_port = "unknown", None
    
    try:
        # use anyio's recommended way to get peer name for better compatibility
        peername = client_stream.extra(anyio.abc.SocketAttribute.peername)
        if isinstance(peername, (tuple, list)) and len(peername) >= 2:
            client_addr, client_port = peername[:2]
        elif isinstance(peername, str):
            # handle unix domain sockets if they are ever used
            client_addr = peername
            client_port = 0 # unix sockets don't have a port
    except Exception:
        # if we can't get the peername, we just log it as unknown.
        # this isn't critical for the proxy to function.
        pass
    
    # register this new tcp connection to get a unique id and a dedicated data queue
    reg_result = manager.register_tcp_sub_connection(tunnel_id)
    if not reg_result:
        print(f"error:    could not register sub-connection for tunnel {tunnel_id}, closing.")
        return
    sub_connection_id, response_queue = reg_result
    
    # log connection open
    network_logger.log_event(NetworkEvent(
        timestamp=time.time(),
        event_type=NetworkEventType.CONNECTION_OPEN,
        tunnel_id=tunnel_id,
        client_ip=client_addr,
        port=client_port,
        protocol="tcp"
    ))
    
    print(f"info:     new tcp connection for tunnel {tunnel_id} from {client_addr}:{client_port}")
    
    packet_count_in = 0
    packet_count_out = 0
    bytes_in = 0
    bytes_out = 0
    start_time = time.time()
    
    try:
        async with anyio.create_task_group() as tg:
            async def public_to_ws():
                nonlocal packet_count_in, bytes_in
                try:
                while True:
                    data = await client_stream.receive(4096)
                        if not data: 
                            break
                        
                        packet_count_in += 1
                        bytes_in += len(data)
                        
                        # log tcp packet
                        network_logger.log_event(NetworkEvent(
                            timestamp=time.time(),
                            event_type=NetworkEventType.TCP_PACKET,
                            tunnel_id=tunnel_id,
                            client_ip=client_addr,
                            bytes_transferred=len(data),
                            direction="in",
                            protocol="tcp",
                            metadata={"packet_number": packet_count_in}
                        ))
                        
                        print(f"tcp:      tunnel {tunnel_id[:8]} → client: packet #{packet_count_in}, {len(data)} bytes (total: {bytes_in} bytes)")
                        
                        print(f"debug:    forwarding {len(data)} bytes to client via websocket")
                        await manager.forward_to_client(tunnel_id, data, sub_connection_id)
                except (anyio.EndOfStream, anyio.BrokenResourceError, anyio.ClosedResourceError):
                    # client disconnected cleanly
                    pass
                except Exception as e:
                    print(f"debug:    public_to_ws task error: {e}")
                finally:
                tg.cancel_scope.cancel()

            async def ws_to_public():
                nonlocal packet_count_out, bytes_out
                try:
                    while True:
                        try:
                            print(f"debug:    waiting for response from client via websocket...")
                            response_data = await response_queue.get()
                            if response_data is None: 
                                print(f"debug:    received None from response queue, breaking")
                                break
                            
                            packet_count_out += 1
                            bytes_out += len(response_data)
                            
                            # log tcp packet
                            network_logger.log_event(NetworkEvent(
                                timestamp=time.time(),
                                event_type=NetworkEventType.TCP_PACKET,
                                tunnel_id=tunnel_id,
                                client_ip=client_addr,
                                bytes_transferred=len(response_data),
                                direction="out",
                                protocol="tcp",
                                metadata={"packet_number": packet_count_out}
                            ))
                            
                            print(f"tcp:      tunnel {tunnel_id[:8]} ← client: packet #{packet_count_out}, {len(response_data)} bytes (total: {bytes_out} bytes)")
                            print(f"debug:    sending {len(response_data)} bytes back to external client")
                            
                    await client_stream.send(response_data)
                        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                            # client disconnected
                            break
                except Exception as e:
                    print(f"debug:    ws_to_public task error: {e}")
                finally:
                tg.cancel_scope.cancel()

            tg.start_soon(public_to_ws)
            tg.start_soon(ws_to_public)
            
    except anyio.get_cancelled_exc_class():
        # task group was cancelled, this is expected
        pass
    except Exception as e:
        # log connection error
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.ERROR,
            tunnel_id=tunnel_id,
            client_ip=client_addr,
            port=client_port,
            protocol="tcp",
            error_message=f"error in tcp handler: {e}"
        ))
    finally:
        # ensure the queue for this sub-connection is removed on exit
        manager.unregister_tcp_sub_connection(tunnel_id, sub_connection_id)

        # also notify the client to close this sub-connection as well
        asyncio.create_task(
            manager.send_control_message_to_client(tunnel_id, sub_connection_id, b'C')
        )

        duration = time.time() - start_time
        # log connection close
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.CONNECTION_CLOSE,
            tunnel_id=tunnel_id,
            client_ip=client_addr,
            protocol="tcp",
            metadata={
                "duration": duration,
                "packets_in": packet_count_in,
                "packets_out": packet_count_out,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out
            }
        ))
        
        print(f"info:     tcp connection closed for tunnel {tunnel_id}: {packet_count_in} packets in ({bytes_in} bytes), {packet_count_out} packets out ({bytes_out} bytes)")
        
        # ensure client stream is properly closed
        try:
        await client_stream.aclose()
        except:
            pass

async def start_tcp_listener(tunnel_id: str, port: int):
    """starts a dedicated tcp listener for a single tunnel on a specific port."""
    try:
        # create listener with SO_REUSEADDR to allow immediate port reuse
        # explicitly bind to all interfaces (0.0.0.0) to allow external access
        listener = await anyio.create_tcp_listener(local_host='0.0.0.0', local_port=port, reuse_port=True)
        print(f"info:     tcp listener started for tunnel {tunnel_id} on 0.0.0.0:{port}")
        handler = lambda client: tcp_proxy_handler(client, tunnel_id)
        await listener.serve(handler)
    except Exception as e:
        # log listener error
        network_logger.log_event(NetworkEvent(
            timestamp=time.time(),
            event_type=NetworkEventType.ERROR,
            tunnel_id=tunnel_id,
            port=port,
            error_message=f"could not start tcp listener on port {port}: {e}",
            protocol="tcp"
        ))
        
        print(f"error:    could not start tcp listener on port {port}: {e}")
