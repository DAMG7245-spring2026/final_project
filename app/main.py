"""FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import get_settings
from app.routers import (
    actor_router,
    brief_router,
    cve_router,
    graph_attack_path_router,
    graph_query_router,
    health_router,
    hybrid_search_router,
    query_router,
    technique_router,
    vector_search_router,
)
from app.services.bm25_index import load_or_build_bm25_index

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    logger.info("Starting PE Org-AI-R Platform...")
    settings = get_settings()
    logger.info(f"Environment: {'DEBUG' if settings.debug else 'PRODUCTION'}")

    try:
        index = load_or_build_bm25_index()
        logger.info(f"BM25 index ready: {index.num_docs} docs")
    except Exception as e:
        logger.error(f"Failed to initialize BM25 index: {e}", exc_info=True)

    yield
    # Shutdown
    logger.info("Shutting down PE Org-AI-R Platform...")


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
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
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