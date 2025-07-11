import asyncio
from fastapi import FastAPI, Request, Response, WebSocket
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
import time
from starlette.middleware.base import BaseHTTPMiddleware

# import rate limiting components
from server.ratelimit import limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware

# import all the application routers
from server.components import (
    auth,
    tunnels,
    nodes,
    admin,
    internal,
    registration,
    node_control,
    telemetry,
)
from server import garbage_collector
from server import config

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        print(f"Request: {request.method} {request.url} headers={dict(request.headers)}")
        
        if request.url.path.startswith("/ws") or "upgrade" in str(request.headers).lower():
            print(f"WebSocket request detected: {request.url}")
        
        response = await call_next(request)
        process_time = time.time() - start_time
        print(f"Response: {response.status_code} in {process_time:.4f}s")
        return response

# --- app initialization ---

app = FastAPI(
    title="tunnelite backend",
    description="the central api server for the tunnelite service.",
    version="0.1.0",
)

# add logging middleware first
app.add_middleware(LoggingMiddleware)

# note: rate limiting middleware disabled because it blocks websockets with 403

# add https redirect middleware if enabled.
# note: this is only useful if you also listen on port 80.
# if your server only listens on 443, this middleware is not strictly necessary
# but adds a layer of defense.
if config.get("ENFORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)


# include all the application routers
app.include_router(auth.router)
app.include_router(tunnels.router)
app.include_router(nodes.router)
app.include_router(admin.router)
app.include_router(internal.router)
app.include_router(registration.router)
app.include_router(node_control.router)
app.include_router(telemetry.router)

# --- startup events ---

@app.on_event("startup")
async def startup_event():
    """on startup, start the garbage collection background task."""
    print("info:     starting garbage collector background task...")
    # run garbage collection every 10 minutes
    asyncio.create_task(garbage_collector.run_periodically(interval=600))

# debug test route
@app.get("/registration/test")
async def test_registration_router():
    return {"message": "registration router is working"}

# debug websocket test
@app.websocket("/test-ws")
async def test_websocket(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("websocket test working")
    await websocket.close()
