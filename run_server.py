# config loader replaces env vars
import sys
import uvicorn
import os

# these imports are now relative to the project root
from server.main import app as fastapi_app
from server import config

# --- configuration ---
# the host to bind to. '0.0.0.0' makes it accessible from outside.
HOST = "0.0.0.0"
# the custom port the api server will listen on for secure traffic.
PORT = 443
# paths to the ssl certificate files for the main api domain (e.g., api.tunnelite.net)
CERT_FILE = "ssl/api_cert.pem"
KEY_FILE = "ssl/api_key.pem"

# --- main entrypoint ---
if __name__ == "__main__":
    print("info:     starting tunnelite main api server...")

    # --- pre-flight checks ---

    # 1. ensure the admin key is set, as it's critical for security.
    if not config.get("TUNNELITE_ADMIN_KEY"):
        sys.exit("error: critical admin key missing in values.json")

    # 2. ensure ssl certificates exist before attempting to start the server.
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        sys.exit(f"error: ssl certificate '{CERT_FILE}' or key '{KEY_FILE}' not found.")

    # --- server configuration ---
    # programmatically configure uvicorn to run the fastapi app with tls.
    # this is the equivalent of running from the command line, but in a controlled script.
    config = uvicorn.Config(
        app=fastapi_app,
        host=HOST,
        port=PORT,
        log_level="info",
        access_log=True,
        ws_ping_interval=20,
        ws_ping_timeout=20,
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
    )

    server = uvicorn.Server(config)

    # run the server. uvicorn will handle the async event loop.
    try:
        # uvicorn's 'run' method is synchronous in this context,
        # so we don't need asyncio.run() here.
        server.run()
    except KeyboardInterrupt:
        print("\ninfo:     shutting down main server.")
    except Exception as e:
        print(f"error:    failed to start server: {e}")
