import time
import logging
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# In-memory fallback storage
_memory_db = {}
_memory_lock = asyncio.Lock()

class RateLimiter:
    redis_client = None
    use_redis = False

    @classmethod
    async def init(cls):
        if not REDIS_URL:
            logger.info("No REDIS_URL configured. Using in-memory rate limiter.")
            cls.use_redis = False
            return
        
        try:
            from redis.asyncio import from_url
            cls.redis_client = from_url(REDIS_URL, decode_responses=True)
            # Test connection
            await cls.redis_client.ping()
            cls.use_redis = True
            logger.info("Redis Rate Limiter initialized successfully.")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Falling back to in-memory rate limiter.")
            cls.redis_client = None
            cls.use_redis = False

    @classmethod
    async def is_rate_limited(cls, key: str, limit: int = 30, window: int = 60) -> bool:
        """
        Check if a given key has exceeded the rate limit.
        Returns:
            True if rate limited (blocked), False if allowed.
        """
        now = time.time()
        
        # Initialize if not initialized yet
        if cls.redis_client is None and not cls.use_redis and REDIS_URL:
            # We run a run-once init attempt
            pass

        if cls.use_redis and cls.redis_client:
            try:
                redis_key = f"rate_limit:{key}"
                # Remove timestamps older than current window
                await cls.redis_client.zremrangebyscore(redis_key, 0, now - window)
                # Count current items
                current_count = await cls.redis_client.zcard(redis_key)
                
                if current_count >= limit:
                    return True
                
                # Add current request (use timestamp as both score and member string)
                await cls.redis_client.zadd(redis_key, {str(now): now})
                # Set TTL on key
                await cls.redis_client.expire(redis_key, window)
                return False
            except Exception as e:
                logger.error(f"Redis rate limiting error: {e}. Falling back to in-memory rate limiter.")
                # Fall through to memory fallback

        # In-memory sliding window fallback
        async with _memory_lock:
            if key not in _memory_db:
                _memory_db[key] = []
            
            # Prune elements older than window
            cutoff = now - window
            _memory_db[key] = [t for t in _memory_db[key] if t > cutoff]
            
            if len(_memory_db[key]) >= limit:
                return True
            
            _memory_db[key].append(now)
            return False
