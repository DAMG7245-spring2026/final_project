"""Redis caching service."""
import json
import logging
from typing import Optional, Type, TypeVar
import redis
from pydantic import BaseModel
from app.config import get_settings

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class RedisCache:
    """Redis caching service with Pydantic model support."""
    
    def __init__(self, host: str, port: int, db: int = 0):
        self.client = redis.Redis(
            host=host, 
            port=port, 
            db=db,
            decode_responses=True
        )
        self._connected = False
    
    def connect(self) -> bool:
        """Test and establish connection."""
        try:
            self.client.ping()
            self._connected = True
            return True
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            self._connected = False
            return False
    
    async def health_check(self) -> tuple[bool, Optional[str]]:
        """Check if Redis connection is healthy."""
        try:
            self.client.ping()
            return True, None
        except Exception as e:
            return False, str(e)
    
    def get(self, key: str, model: Type[T]) -> Optional[T]:
        """Get cached item and deserialize to Pydantic model."""
        try:
            data = self.client.get(key)
            if data:
                return model.model_validate_json(data)
            return None
        except Exception as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None
    
    def get_raw(self, key: str) -> Optional[str]:
        """Get raw cached value."""
        try:
            return self.client.get(key)
        except Exception as e:
            logger.warning(f"Cache get error for {key}: {e}")
            return None
    
    def set(self, key: str, value: BaseModel, ttl_seconds: int) -> bool:
        """Cache Pydantic model with TTL."""
        try:
            self.client.setex(key, ttl_seconds, value.model_dump_json())
            return True
        except Exception as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False
    
    def set_raw(self, key: str, value: str, ttl_seconds: int) -> bool:
        """Cache raw string value with TTL."""
        try:
            self.client.setex(key, ttl_seconds, value)
            return True
        except Exception as e:
            logger.warning(f"Cache set error for {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Invalidate cache entry."""
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for {key}: {e}")
            return False
    
    def delete_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern."""
        try:
            count = 0
            for key in self.client.scan_iter(match=pattern):
                self.client.delete(key)
                count += 1
            return count
        except Exception as e:
            logger.warning(f"Cache delete pattern error for {pattern}: {e}")
            return 0
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        try:
            return bool(self.client.exists(key))
        except Exception:
            return False


# Cache key prefixes
class CacheKeys:
    """Cache key constants and builders."""
    COMPANY = "company"
    INDUSTRY = "industry"
    INDUSTRIES_LIST = "industries:list"
    ASSESSMENT = "assessment"
    DIMENSION_WEIGHTS = "config:dimension_weights"
    
    @staticmethod
    def company(company_id: str) -> str:
        return f"company:{company_id}"
    
    @staticmethod
    def industry(industry_id: str) -> str:
        return f"industry:{industry_id}"
    
    @staticmethod
    def assessment(assessment_id: str) -> str:
        return f"assessment:{assessment_id}"


# Singleton instance
_redis_cache: Optional[RedisCache] = None


def get_redis_cache() -> RedisCache:
    """Get or create Redis cache singleton."""
    global _redis_cache
    if _redis_cache is None:
        settings = get_settings()
        _redis_cache = RedisCache(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db
        )
    return _redis_cache