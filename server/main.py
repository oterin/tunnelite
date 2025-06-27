import asyncio
import os
from fastapi import Depends, FastAPI, Request, HTTPException, status

from server.ratelimit import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware

# import all the routers from the components
from server.components import (
    auth,
    tunnels,
    nodes,
    admin,
    internal,
    registration,
    node_control,
)
from server import garbage_collector

# --- global dependencies ---

async def enforce_https(request: Request):
    """
    a fastapi dependency that enforces https connections for all http requests.
    it inspects the 'x-forwarded-proto' header from a reverse proxy.
    it explicitly ignores websocket connections.
    """
    # do not apply this check to websockets, as they have their own wss:// scheme
    if request.scope.get("type") == "websocket":
        return

    if os.getenv("ENFORCE_HTTPS", "false").lower() == "true":
        if request.headers.get("x-forwarded-proto") != "https":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insecure connections are not allowed. please use https.",
            )

# --- app initialization ---

app = FastAPI(
    title="tunnelite backend",
    description="the central api server for the tunnelite service.",
    version="0.1.0",
    # this correctly applies the dependency to all http routes
    dependencies=[Depends(enforce_https)],
)

# add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# include all the application routers
app.include_router(auth.router)
app.include_router(tunnels.router)
app.include_router(nodes.router)
app.include_router(admin.router)
app.include_router(internal.router)
app.include_router(registration.router)
app.include_router(node_control.router)

# --- startup events ---

@app.on_event("startup")
async def startup_event():
    """on startup, start the garbage collection background task."""
    print("info:     starting garbage collector background task...")
    # run garbage collection every 10 minutes
    asyncio.create_task(garbage_collector.run_periodically(interval=600))
