import asyncio
import uvicorn
from tunnel_node.main import app as fastapi_app
from tunnel_node.proxy_server import run_http_proxy_server
from tunnel_node.connection_manager import manager
from tunnel_node.config import NODE_PUBLIC_ADDRESS

async def main():
    """
    this is the main entrypoint for running a tunnelite node.

    it starts both the fastapi control plane server and the data plane proxy server,
    allowing them to run concurrently in the same process and share state via the
    connection manager.
    """
    # programmatically configure uvicorn to run the fastapi app.
    # this gives us more control than running it from the command line.
    # we extract the host and port from the node's configured public address.
    try:
        # handle urls like http://0.0.0.0:8001
        host, port_str = NODE_PUBLIC_ADDRESS.split("//")[1].split(":")
        port = int(port_str)
    except (IndexError, ValueError):
        print(f"error:    invalid node_public_address format: {NODE_PUBLIC_ADDRESS}. expected format like http://host:port")
        return

    config = uvicorn.Config(
        app=fastapi_app,
        host=host,
        port=port,
        log_level="info"
    )
    server = uvicorn.Server(config)

    # run both the fastapi server and our proxy servers concurrently.
    # they will share the same 'manager' instance, allowing them to communicate.
    await asyncio.gather(
        server.serve(),
        run_http_proxy_server(manager)
    )

if __name__ == "__main__":
    print("info:     starting tunnelite node...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\ninfo:     shutting down node.")
