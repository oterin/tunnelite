from ast import Return
import anyio
from .connection_manager import ConnectionManager

PROXY_PORT = 8080

async def http_proxy_handler(client_stream: anyio.abc.SocketStream, manager: ConnectionManager):
    """handles a single public http request from start to finish"""
    hostname = ""
    try:
        # 1. read the incoming request and parse the host header
        request_data = await client_stream.receive(4096)
        if not request_data:
            return

        headers = request_data.decode('utf-8', errors='ignore').split('\r\n')
        for header in headers:
            if header.lower().startswith('host'):
                hostname = header.split(':', 1)[1].strip()
                break
        if not hostname:
            await client_stream.send(b"HTTP/1.1 400 Bad Request\r\n\r\nHost header is missing.")
            return

        # 2. forward the request to the correct client via the connection manager
        await manager.forward_to_client(hostname, request_data)

        # 3. wait for the response to come back from the client
        response_data = await manager.get_response_from_client(hostname)

        # 4. write the client's response back to the original requester
        await client_stream.send(response_data)

    except Exception as e:
        print(f"error:    proxy handler failed for {hostname}: {e}")
    finally:
        await client_stream.aclose()

async def run_proxy_server(manager: ConnectionManager):
    """starts the main tcp proxy server"""
    listener = await anyio.create_tcp_listener(local_port=PROXY_PORT)
    print(f"info:     http proxy server listening on 127.0.0.1:{PROXY_PORT}")
    await listener.serve(lambda client: http_proxy_handler(client, manager))
