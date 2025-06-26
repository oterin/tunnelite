import asyncio
import os
import ssl
import sys
import pwd
import grp
from multiprocessing import Process, cpu_count
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import anyio
import uvicorn

# these imports are now relative to the project root
from tunnel_node.connection_manager import manager
from tunnel_node.main import app as fastapi_app
from tunnel_node.proxy_server import http_proxy_handler

# --- configuration ---
# the unprivileged user and group to drop to after binding sockets.
# you must create this user on your system:
# `sudo useradd --system --no-create-home tunnelite`
DROP_TO_USER = "tunnelite"
DROP_TO_GROUP = "tunnelite"

# standard ports for web traffic
HTTP_PORT = 80
HTTPS_PORT = 443

# --- security and process management functions ---

def drop_privileges(uid_name: str, gid_name: str):
    """drops root privileges to a specified user and group."""
    try:
        new_uid = pwd.getpwnam(uid_name).pw_uid
        new_gid = grp.getgrnam(gid_name).gr_gid
    except KeyError:
        sys.exit(f"error: user '{uid_name}' or group '{gid_name}' not found. please create them first.")

    os.setgid(new_gid)
    os.setuid(new_uid)
    print(f"info:     process privileges dropped to {uid_name}:{gid_name} (pid: {os.getpid()})")

def get_ssl_context():
    """creates an ssl context that loads the server's certificate."""
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ssl/cert.pem", keyfile="ssl/key.pem")
        # in the future, you could add acme logic here for auto-renewal
        print("info:     ssl certificates loaded successfully.")
        return context
    except FileNotFoundError:
        print("warn:     ssl certificates not found in 'ssl/' directory. https server will not be started.")
        return None
    except Exception as e:
        print(f"error:    failed to load ssl certificates: {e}")
        return None

# --- server startup logic for worker processes ---

async def run_fastapi_server(sock: socket):
    """starts the uvicorn/fastapi control plane server on a pre-bound socket."""
    config = uvicorn.Config(app=fastapi_app, log_level="info", lifespan="off")
    server = uvicorn.Server(config)
    await server.serve(sockets=[sock])


async def run_https_proxy(sock: socket):
    """starts the https data plane proxy on a pre-bound http socket that will be wrapped with tls."""
    ssl_context = get_ssl_context()
    if not ssl_context:
        return

    # the handler is told this is a secure connection to add necessary headers
    handler = lambda client: http_proxy_handler(client, manager, is_secure=True)
    try:
        listener = await anyio.create_tcp_listener(sock=sock)
        await listener.serve(handler, tls_standard_compatible=False, ssl_context=ssl_context)
    except Exception as e:
        print(f"error:    https proxy failed to start: {e}")


def start_worker_process(http_socket: socket, https_socket: socket):
    """the main entrypoint for each worker process."""
    print(f"info:     worker process started (pid: {os.getpid()})")

    # first thing a worker does is drop privileges
    drop_privileges(DROP_TO_USER, DROP_TO_GROUP)

    async def run_servers():
        # run both the control plane (fastapi) and data plane (proxy) concurrently
        async with anyio.create_task_group() as tg:
            # uvicorn runs on the http socket (for redirection or internal health checks)
            tg.start_soon(run_fastapi_server, http_socket)
            print(f"info:     fastapi server started on port {HTTP_PORT} (pid: {os.getpid()})")

            # our custom proxy runs on the https socket
            tg.start_soon(run_https_proxy, https_socket)
            print(f"info:     https proxy server started on port {HTTPS_PORT} (pid: {os.getpid()})")

            # here you could start other listeners for non-proxied tcp/udp traffic

    try:
        asyncio.run(run_servers())
    except KeyboardInterrupt:
        pass

# --- main entrypoint ---

if __name__ == "__main__":
    if sys.platform == "win32":
        sys.exit("error: production entrypoint is not supported on windows.")

    if os.geteuid() != 0:
        sys.exit("error: this script must be run as root to bind privileged ports.")

    print("info:     starting tunnelite production node...")

    # 1. bind sockets while we still have root privileges
    try:
        # http socket for fastapi/uvicorn
        http_socket = socket(AF_INET, SOCK_STREAM)
        http_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        http_socket.bind(('', HTTP_PORT))
        http_socket.listen(128)
        print(f"info:     http socket bound to 0.0.0.0:{HTTP_PORT}")

        # https socket for our custom proxy
        https_socket = socket(AF_INET, SOCK_STREAM)
        https_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        https_socket.bind(('', HTTPS_PORT))
        https_socket.listen(128)
        print(f"info:     https socket bound to 0.0.0.0:{HTTPS_PORT}")

    except PermissionError:
        sys.exit(f"error: permission denied to bind sockets. this script must be run as root.")
    except Exception as e:
        sys.exit(f"error: failed to bind sockets: {e}")

    # 2. spawn worker processes
    num_workers = cpu_count()
    print(f"info:     spawning {num_workers} worker processes...")
    workers = []
    for _ in range(num_workers):
        worker = Process(target=start_worker_process, args=(http_socket, https_socket))
        workers.append(worker)
        worker.start()

    # 3. wait for workers to finish (they won't, unless interrupted)
    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main process...")
        for worker in workers:
            worker.terminate()
            worker.join()

    print("info:     main process exited.")
