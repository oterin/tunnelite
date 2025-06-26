import asyncio
import os
import ssl
import sys
import pwd
import grp
from multiprocessing import Process, cpu_count
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

import uvicorn

# these imports are now relative to the project root
from tunnel_node.main import app as fastapi_app

# --- configuration ---
# the unprivileged user and group to drop to after binding sockets.
# you must create this user on your system first, e.g.:
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

    os.setgroups([])  # drop any supplementary groups
    os.setgid(new_gid)
    os.setuid(new_uid)
    os.umask(0o077)
    print(f"info:     (pid: {os.getpid()}) process privileges dropped to {uid_name}:{gid_name}")

def get_ssl_context():
    """creates an ssl context that loads the server's certificate."""
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="ssl/cert.pem", keyfile="ssl/key.pem")
        print(f"info:     (pid: {os.getpid()}) ssl certificates loaded successfully.")
        return context
    except FileNotFoundError:
        print(f"warn:     (pid: {os.getpid()}) ssl certificates not found in 'ssl/' directory. https will not be served.")
        return None
    except Exception as e:
        print(f"error:    (pid: {os.getpid()}) failed to load ssl certificates: {e}")
        return None

# --- server startup logic for worker processes ---

def start_worker_process(http_socket: socket, https_socket: socket):
    """the main entrypoint for each worker process."""
    print(f"info:     worker process started (pid: {os.getpid()})")

    # first thing a worker does is drop privileges
    drop_privileges(DROP_TO_USER, DROP_TO_GROUP)

    # get ssl context, this will determine if we can serve https
    ssl_context = get_ssl_context()

    # configure uvicorn to listen on both sockets if possible
    config = uvicorn.Config(
        app=fastapi_app,
        log_level="info",
        lifespan="off",
        # pass the file descriptors of the pre-bound sockets
        fds=[http_socket.fileno(), https_socket.fileno()] if ssl_context else [http_socket.fileno()],
        # pass ssl context only if it was loaded successfully
        ssl_keyfile= "ssl/key.pem" if ssl_context else None,
        ssl_certfile= "ssl/cert.pem" if ssl_context else None,
    )

    server = uvicorn.Server(config)

    # run the server
    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        pass


# --- main entrypoint ---

if __name__ == "__main__":
    if sys.platform == "win32":
        sys.exit("error: production entrypoint is not supported on windows.")

    if os.geteuid() != 0:
        sys.exit("error: this script must be run as root to bind privileged ports.")

    print("info:     starting tunnelite production node...")

    # sockets must be created and bound before forking, so they can be inherited.
    try:
        http_socket = socket(AF_INET, SOCK_STREAM)
        http_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        http_socket.bind(('', HTTP_PORT))
        http_socket.listen(128)
        print(f"info:     http socket bound to 0.0.0.0:{HTTP_PORT} by main process (pid: {os.getpid()})")

        https_socket = socket(AF_INET, SOCK_STREAM)
        https_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        https_socket.bind(('', HTTPS_PORT))
        https_socket.listen(128)
        print(f"info:     https socket bound to 0.0.0.0:{HTTPS_PORT} by main process (pid: {os.getpid()})")

    except PermissionError:
        sys.exit(f"error: permission denied to bind sockets. this script must be run as root.")
    except Exception as e:
        sys.exit(f"error: failed to bind sockets: {e}")

    num_workers = cpu_count()
    print(f"info:     spawning {num_workers} worker processes...")
    workers = []
    for _ in range(num_workers):
        worker = Process(target=start_worker_process, args=(http_socket, https_socket))
        workers.append(worker)
        worker.start()

    # close the sockets in the parent process immediately after forking.
    # the child processes have their own copies of the file descriptors.
    http_socket.close()
    https_socket.close()

    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main process...")
        for worker in workers:
            worker.terminate()
            worker.join()

    print("info:     main process exited.")
