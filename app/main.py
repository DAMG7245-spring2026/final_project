"""FastAPI application entry point."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.logging_config import configure_logging, get_logger
from app.routers import (
    actor_router,
    advisory_router,
    brief_router,
    cve_router,
    graph_attack_path_router,
    graph_query_router,
    health_router,
    hybrid_search_router,
    query_router,
    technique_router,
    vector_search_router,
    weekly_brief_router,
    weekly_digest_router,
)
from app.services.bm25_index import load_or_build_bm25_index

# Configure structured logging (structlog + stdlib interop) once at import time.
# Importing app.main from uvicorn, tests, or scripts all go through this path,
# so third-party libs that log via stdlib also land in the same pipeline.
configure_logging()
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    settings = get_settings()
    log.info(
        "app_startup",
        app_name=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
    )

    try:
        index = load_or_build_bm25_index()
        log.info("bm25_index_ready", num_docs=index.num_docs)
    except Exception as e:
        log.exception("bm25_index_init_failed", error=str(e))

    yield
    log.info("app_shutdown")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title=settings.app_name,
        description="""
        ## PE Org-AI-R Platform API
        
        AI-Readiness Assessment Platform for Private Equity
        
        ### CTI knowledge graph (structured)
        - **CVE**, **Actor**, **Technique** detail from Neo4j
        - **Attack-path** traversal (`/graph/attack-path`)
        - **Search**: hybrid BM25 + vector over advisory chunks (`/search/...`)
        - **NL query** (`POST /query`) and **weekly brief** (`GET /brief/weekly`) are stubs until advisory data is in Neo4j
        """,
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(health_router)
    app.include_router(cve_router)
    app.include_router(actor_router)
    app.include_router(technique_router)
    app.include_router(graph_attack_path_router)
    app.include_router(query_router)
    app.include_router(brief_router)
    app.include_router(vector_search_router)
    app.include_router(hybrid_search_router)
    app.include_router(graph_query_router)
    app.include_router(weekly_digest_router)
    app.include_router(weekly_brief_router)
    app.include_router(advisory_router)

    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log.exception(
            "unhandled_exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(exc)}
        )
    
    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)