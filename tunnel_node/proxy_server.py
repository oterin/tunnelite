from ast import Return
import anyio
import ssl
from .connection_manager import ConnectionManager

# standard http/s ports
HTTP_PORT = 80
HTTPS_PORT = 443
LOCAL_TEST_PORT = 8080

def get_ssl_context():
    """creates an ssl context that loads the server's certificate."""
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # you must replace these with the actual paths to your wildcard cert and key
        context.load_cert_chain(certfile="ssl/cert.pem", keyfile="ssl/key.pem")
        return context
    except FileNotFoundError:
        print("warn:     ssl certificates not found. https proxy will not be started.")
        return None

async def http_proxy_handler(client_stream: anyio.abc.SocketStream, manager: ConnectionManager):
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

        # 3. forward the request to the correct client via the connection manager
        await manager.forward_to_client(manager.tunnels_by_hostname[hostname].tunnel_id, request_data)

        # 4. wait for the response to come back from the client
        response_data = await manager.get_response_from_client(hostname)

        # 5. write the client's response back to the original requester
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
                # this reads from the response queue where the client puts incoming data
                while True:
                    response_data = await manager.get_response_from_client(tunnel_id, is_tcp=True)
                    if not response_data:
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


async def run_proxy_servers(manager: ConnectionManager):
    """starts all proxy servers concurrently."""
    ssl_context = get_ssl_context()
    handler = lambda client: http_proxy_handler(client, manager)

    async with anyio.create_task_group() as tg:
        # start local test http proxy on 8080
        listener_local = await anyio.create_tcp_listener(local_port=LOCAL_TEST_PORT)
        tg.start_soon(listener_local.serve, handler)
        print(f"info:     local http proxy server listening on 127.0.0.1:{LOCAL_TEST_PORT}")

        # start public http proxy on port 80
        try:
            listener_http = await anyio.create_tcp_listener(local_port=HTTP_PORT)
            tg.start_soon(listener_http.serve, handler)
            print(f"info:     public http proxy server listening on 0.0.0.0:{HTTP_PORT}")
        except PermissionError:
            print(f"warn:     permission denied to bind to port {HTTP_PORT}. run with sudo or as root.")

        # start public https proxy on port 443 if ssl context is available
        if ssl_context:
            try:
                listener_https = await anyio.create_tcp_listener(local_port=HTTPS_PORT, tls=True, tls_standard_compatible=False)
                tg.start_soon(listener_https.serve, handler, ssl_context)
                print(f"info:     public https proxy server listening on 0.0.0.0:{HTTPS_PORT}")
            except PermissionError:
                print(f"warn:     permission denied to bind to port {HTTPS_PORT}. run with sudo or as root.")
            except Exception as e:
                print(f"error:    could not start https proxy: {e}")
