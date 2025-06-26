from fastapi import Request, HTTPException, status

async def enforce_https(request: Request):
    """
    a fastapi dependency that enforces https connections in a production environment.

    this function checks for the 'x-forwarded-proto' header, which is a standard
    header added by reverse proxies (like nginx, heroku, aws alb) to indicate the
    protocol of the original request.

    if the `enforce_https` flag is set and the protocol is not 'https', it rejects
    the request, ensuring that the application only accepts secure traffic.
    """
    # this check is based on the 'x-forwarded-proto' header.
    # in a real deployment, a reverse proxy would handle tls termination
    # and set this header to 'https' for encrypted requests.
    if request.headers.get("x-forwarded-proto") != "https":
        # we also check the direct scheme for local development without a proxy
        if request.url.scheme != "https":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="insecure connections are not allowed. please use https.",
            )
