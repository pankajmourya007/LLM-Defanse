import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.db import check_and_create_tables
from app.services.rate_limiter import RateLimiter
from app.routes import auth, llm, analytics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Starting up LLM-Defanc Security Gateway...")
    
    # Resiliently initialize database and rate limiter
    await check_and_create_tables()
    await RateLimiter.init()
    
    yield
    # Shutdown actions (if any)
    logger.info("Shutting down LLM-Defanc Security Gateway...")

app = FastAPI(
    title="LLM-Defanc Security Gateway API",
    description="Enterprise AI Gateway offering PII protection, Injection detection, and detailed Audit Logging.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration to support local development on Vite / React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Supports wildcards for flexibility in MVP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(auth.router)
app.include_router(llm.router)
app.include_router(analytics.router)

@app.get("/")
def read_root():
    return {
        "status": "healthy",
        "service": "LLM-Defanc Security Gateway",
        "documentation": "/docs"
    }
