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
# these imports are now relative to the project root
from tunnel_node.main import app as fastapi_app, on_startup as fastapi_startup

# --- configuration ---
# the unprivileged user and group to drop to after binding sockets.
# you must create this user on your system first, e.g.:
# `sudo useradd --system --no-create-home tunnelite`
DROP_TO_USER = "tunnelite"
DROP_TO_GROUP = "tunnelite"

# standard port for secure web traffic
HTTPS_PORT = 443
CERT_FILE = "ssl/cert.pem"
KEY_FILE = "ssl/key.pem"


def drop_privileges(uid_name: str, gid_name: str):
    """drops root privileges to a specified user and group for security."""
    try:
        new_uid = pwd.getpwnam(uid_name).pw_uid
        new_gid = grp.getgrnam(gid_name).gr_gid
    except KeyError:
        sys.exit(f"error: user '{uid_name}' or group '{gid_name}' not found. please create them first.")

    # drop any supplementary groups
    os.setgroups([])
    # set the new group and user id
    os.setgid(new_gid)
    os.setuid(new_uid)
    # set a secure umask
    os.umask(0o077)
    print(f"info:     (pid: {os.getpid()}) process privileges dropped to {uid_name}:{gid_name}")


def start_worker_process(https_socket: socket):
    """
    this is the main entrypoint for each worker process. it configures and starts
    the uvicorn server, telling it to use the pre-bound socket.
    """
    print(f"info:     worker process started (pid: {os.getpid()})")

    # first thing a worker does is drop its root privileges.
    drop_privileges(DROP_TO_USER, DROP_TO_GROUP)

    # add the startup events back to the app instance for this worker process.
    # this is safe because each worker has its own independent app instance in memory.
    fastapi_app.add_event_handler("startup", fastapi_startup)

    # configure uvicorn to use the existing socket file descriptor and handle tls.
    # lifespan must be "on" for startup events to fire.
    config = uvicorn.Config(
        app=fastapi_app,
        fd=https_socket.fileno(),
        log_level="info",
        lifespan="on",
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
    )

    server = uvicorn.Server(config)

    # uvicorn's run method takes over from here.
    try:
        server.run()
    except KeyboardInterrupt:
        # parent process handles shutdown signal
        pass


if __name__ == "__main__":
    # platform and privilege checks
    if sys.platform == "win32":
        sys.exit("error: production entrypoint is not supported on windows.")
    if os.geteuid() != 0:
        sys.exit("error: this script must be run as root to bind privileged ports.")

    print("info:     starting tunnelite production node...")

    # pre-flight check: ensure ssl certs exist before we do anything.
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        sys.exit(f"error: ssl certificate '{CERT_FILE}' or key '{KEY_FILE}' not found.")

    # 1. bind the main https socket while we still have root privileges.
    try:
        https_socket = socket(AF_INET, SOCK_STREAM)
        https_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        https_socket.bind(('', HTTPS_PORT))
        https_socket.listen(128)
        print(f"info:     https socket bound to 0.0.0.0:{HTTPS_PORT} by main process (pid: {os.getpid()})")
    except PermissionError:
        sys.exit(f"error: permission denied to bind to port {HTTPS_PORT}. this script must be run as root.")
    except Exception as e:
        sys.exit(f"error: failed to bind socket: {e}")

    # 2. spawn a worker process for each cpu core.
    num_workers = cpu_count()
    print(f"info:     spawning {num_workers} worker processes...")
    workers = []
    for _ in range(num_workers):
        # pass the socket object to the worker process. it will be inherited upon forking.
        worker = Process(target=start_worker_process, args=(https_socket,))
        workers.append(worker)
        worker.start()

    # 3. close the master socket in the parent process.
    # the parent's only job is to manage the workers; it doesn't need the socket.
    # the children have their own inherited copies.
    https_socket.close()

    # 4. wait for workers to finish (they won't, unless interrupted).
    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main process...")
        for worker in workers:
            worker.terminate()
            worker.join()

    print("info:     main process exited.")
