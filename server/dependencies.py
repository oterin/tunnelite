from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp
from fastapi import HTTPException, status

class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """
    a middleware to enforce https connections in a production environment.

    it inspects the 'x-forwarded-proto' header from a reverse proxy.
    if the protocol is not 'https', it rejects the request.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if request.headers.get("x-forwarded-proto") != "https":
            # also check the direct scheme for local development or direct connections
            if request.url.scheme != "https":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="insecure connections are not allowed. please use https.",
                )

        response = await call_next(request)
        return response
