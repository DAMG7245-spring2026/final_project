"""Common models used across the application."""
from typing import Generic, TypeVar, List
from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response model."""
    items: List[T]
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, le=100, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")


class HealthDependency(BaseModel):
    """Health status of a single dependency."""
    status: str
    latency_ms: float | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Overall health status")
    timestamp: str = Field(..., description="ISO timestamp")
    version: str = Field(..., description="Application version")
    dependencies: dict[str, str] = Field(
        ..., 
        description="Status of each dependency"
    )


class ErrorResponse(BaseModel):
    """Standard error response model."""
    detail: str
    error_code: str | None = None
    field: str | None = None


class MessageResponse(BaseModel):
    """Simple message response."""
    message: str
    id: str | None = None