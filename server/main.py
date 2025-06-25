"""
the server
"""

from fastapi import Depends, FastAPI, Request
import os

from server.ratelimit import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware

from server.components import (
    auth,
    tunnels,
    nodes,
    admin,
    internal,
    registration,
)

app = FastAPI(
    title="tunnelite backend",
    description="we tunnelin data in here",
    version="0.1.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.include_router(auth.router)
app.include_router(tunnels.router)
app.include_router(nodes.router)
app.include_router(admin.router)
app.include_router(internal.router)
app.include_router(registration.router)

@app.get("/tunnelite/users/me")
async def me(user: auth.User = Depends(auth.get_current_user)):
    return user
