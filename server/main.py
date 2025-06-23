"""
the server
"""

from fastapi import Depends, FastAPI

from server.components import auth
from server.components.auth import get_current_user

app = FastAPI(
    title="tunnelite backend",
    description="we tunnelin data in here",
    version="0.1.0",
)

app.include_router(auth.router, prefix="/tunnelite")

