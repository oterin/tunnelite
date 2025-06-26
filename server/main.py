"""
the server
"""

import asyncio
from fastapi import Depends, FastAPI, Request, HTTPException, status
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
    node_control,
)
from server import garbage_collector, dependencies

# prepare global dependencies
global_dependencies = []
if os.getenv("ENFORCE_HTTPS", "false").lower() == "true":
    global_dependencies.append(Depends(dependencies.enforce_https))

app = FastAPI(
    title="tunnelite backend",
    description="we tunnelin data in here",
    version="0.1.0",
    dependencies=global_dependencies,
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
app.include_router(node_control.router)

@app.on_event("startup")
async def startup_event():
    """On startup, start the garbage collection background task."""
    print("info:     starting garbage collector background task...")
    # run every 10 minutes
    asyncio.create_task(garbage_collector.run_periodically(interval=600))

@app.get("/tunnelite/users/me")
async def me(user: auth.User = Depends(auth.get_current_user)):
    return user
