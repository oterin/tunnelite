import os

# this is the public-facing ip address and the port that the node's internal
# control plane api will listen on. it must be reachable by the main server.
# this is the only required configuration for a node.
# example: NODE_PUBLIC_ADDRESS="http://198.51.100.10:8001"
NODE_PUBLIC_ADDRESS = os.getenv("NODE_PUBLIC_ADDRESS")

# this is the base url of the main server api.
# it can be overridden for local development, but defaults to the production url.
MAIN_SERVER_URL = os.getenv("TUNNELITE_SERVER_URL", "https://api.tunnelite.net:8220")

# configuration validation
if not all([NODE_PUBLIC_ADDRESS]):
    raise RuntimeError("critical environment variable NODE_PUBLIC_ADDRESS is not set.")
