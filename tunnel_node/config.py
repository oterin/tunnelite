# load config helper
from server import config

# required public-facing address of this node
NODE_PUBLIC_ADDRESS = config.get("NODE_PUBLIC_ADDRESS")

# base url of the main api server
MAIN_SERVER_URL = config.get("TUNNELITE_SERVER_URL", "https://api.tunnelite.net")

# validation
if not NODE_PUBLIC_ADDRESS:
    raise RuntimeError("NODE_PUBLIC_ADDRESS not configured in values.json")
