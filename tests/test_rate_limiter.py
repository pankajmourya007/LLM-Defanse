import pytest
import asyncio
from app.services.rate_limiter import RateLimiter

@pytest.mark.asyncio
async def test_rate_limiter_in_memory():
    # Make sure we use in-memory rate limiter for this test
    RateLimiter.use_redis = False
    RateLimiter.redis_client = None
    
    key = "test_user_key"
    limit = 3
    window = 2  # 2 seconds
    
    # First 3 requests should pass
    r1 = await RateLimiter.is_rate_limited(key, limit=limit, window=window)
    r2 = await RateLimiter.is_rate_limited(key, limit=limit, window=window)
    r3 = await RateLimiter.is_rate_limited(key, limit=limit, window=window)
    
    assert r1 is False
    assert r2 is False
    assert r3 is False
    
    # 4th request should block
    r4 = await RateLimiter.is_rate_limited(key, limit=limit, window=window)
    assert r4 is True
    
    # Wait for window to expire
    await asyncio.sleep(2.1)
    
    # Request should pass again after window expires
    r5 = await RateLimiter.is_rate_limited(key, limit=limit, window=window)
    assert r5 is False
