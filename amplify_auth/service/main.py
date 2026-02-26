"""Main entrypoint for auth service."""

import uvicorn

from .api import app
from .config import settings


def main():
    """Run the auth service."""
    uvicorn.run(
        "amplify_auth.service.api:app",
        host="0.0.0.0",
        port=settings.port,
        reload=False,
        log_level="info"
    )
