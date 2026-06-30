import os
import logging
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./llm_defense.db")

# Fallback mechanism if database connections fail
engine = None
AsyncSessionLocal = None
Base = declarative_base()

def init_engine(db_url: str):
    global engine, AsyncSessionLocal
    # SQLite requires some special arguments for concurrency (e.g., check_same_thread=False)
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    
    engine = create_async_engine(db_url, connect_args=connect_args, echo=False)
    AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    logger.info(f"Initialized database engine with: {db_url.split('@')[-1] if '@' in db_url else db_url}")

# Initialize with configured URL first
init_engine(DATABASE_URL)

async def get_db():
    global AsyncSessionLocal
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def check_and_create_tables():
    global engine, DATABASE_URL
    try:
        # Attempt to run a test connection and create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.error(f"Database connection/creation failed with URL: {DATABASE_URL}. Error: {e}")
        if "sqlite" not in DATABASE_URL:
            logger.warning("Falling back to local SQLite database: sqlite+aiosqlite:///./llm_defense.db")
            DATABASE_URL = "sqlite+aiosqlite:///./llm_defense.db"
            init_engine(DATABASE_URL)
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Local SQLite database tables initialized successfully.")
        else:
            raise e
