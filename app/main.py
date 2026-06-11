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
    
    # Seed default user if database is empty
    from app.database.db import AsyncSessionLocal
    from app.models.user import User
    from app.services.auth import hash_password
    from sqlalchemy.future import select
    
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(User))
            if not result.scalars().first():
                logger.info("No users found. Seeding default credentials...")
                default_user = User(
                    username="admin",
                    hashed_password=hash_password("admin123"),
                    is_active=True
                )
                db.add(default_user)
                await db.commit()
                logger.info("Seeded default test account successfully: admin / admin123")
        except Exception as e:
            logger.error(f"Failed to seed default credentials: {e}")
            
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
