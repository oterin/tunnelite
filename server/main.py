"""
the server
"""

from fastapi import Depends, FastAPI
from dotenv import load_dotenv
import os

load_dotenv()

from server.components import (
    auth,
    tunnels,
    nodes,
    admin
)

app = FastAPI(
    title="tunnelite backend",
    description="we tunnelin data in here",
    version="0.1.0",
)
app.include_router(auth.router, prefix="/tunnelite")
app.include_router(tunnels.router, prefix="/tunnelite")
app.include_router(nodes.router, prefix="/tunnelite")
app.include_router(admin.router, prefix="/tunnelite")
