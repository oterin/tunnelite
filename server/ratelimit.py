from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Create a central Limiter instance.
# The key_func determines how to identify a client. We'll use their IP address.
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
