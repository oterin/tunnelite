import os
from dotenv import load_dotenv

# load_dotenv("tunnel_node/.env")

NODE_ID = os.getenv("NODE_ID")
NODE_LOCATION = os.getenv("NODE_LOCATION")
NODE_PUBLIC_ADDRESS = os.getenv("NODE_PUBLIC_ADDRESS")

MAIN_SERVER_URL = os.getenv("MAIN_SERVER_URL", "https://api.tunnelite.net:8220")

if not all([NODE_ID, NODE_LOCATION, NODE_PUBLIC_ADDRESS]):
    raise RuntimeError("missing environment variables in .env.node")
