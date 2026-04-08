"""Health check endpoint."""
from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.models import HealthResponse
from app.services import get_snowflake_service, get_redis_cache, get_s3_storage

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Check health status of the API and all dependencies."
)
async def health_check():
    """
    Check health of all dependencies.
    
    Returns 200 if all healthy, 503 if any unhealthy.
    """
    settings = get_settings()
    dependencies: dict[str, str] = {}
    
    # Check Snowflake
    try:
        snowflake = get_snowflake_service()
        sf_healthy, sf_error = await snowflake.health_check()
        dependencies["snowflake"] = "healthy" if sf_healthy else f"unhealthy: {sf_error}"
    except Exception as e:
        dependencies["snowflake"] = f"unhealthy: {str(e)}"
    
    # Check Redis
    try:
        redis = get_redis_cache()
        redis_healthy, redis_error = await redis.health_check()
        dependencies["redis"] = "healthy" if redis_healthy else f"unhealthy: {redis_error}"
    except Exception as e:
        dependencies["redis"] = f"unhealthy: {str(e)}"
    
    # Check S3
    try:
        s3 = get_s3_storage()
        s3_healthy, s3_error = await s3.health_check()
        dependencies["s3"] = "healthy" if s3_healthy else f"unhealthy: {s3_error}"
    except Exception as e:
        dependencies["s3"] = f"unhealthy: {str(e)}"
    
    # Determine overall status
    all_healthy = all(v == "healthy" for v in dependencies.values())
    overall_status = "healthy" if all_healthy else "degraded"
    
    response = HealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
        version=settings.app_version,
        dependencies=dependencies
    )
    
    # Return 503 if degraded
    if not all_healthy:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=response.model_dump()
        )
    
    return response