"""Routers package - API endpoint routers."""
from .advisories import router as advisories_router
from .health import router as health_router

__all__ = [
    "advisories_router",
    "health_router",
]
