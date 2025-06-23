"""
the server
"""

from fastapi import Depends, FastAPI
import os

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
app.include_router(auth.router)
app.include_router(tunnels.router)
app.include_router(nodes.router)
app.include_router(admin.router)

@app.get("/tunnelite/users/me")
async def me(user: auth.User = Depends(auth.get_current_user)):
    return user
