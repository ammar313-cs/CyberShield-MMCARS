"""
Redis Client - LangCache Integration
Provides async Redis connection for caching, pub/sub, and state management.
"""

import os
from typing import Any, Optional
from contextlib import asynccontextmanager

import redis.asyncio as redis
from redis.asyncio import ConnectionPool
import structlog

logger = structlog.get_logger(__name__)


class RedisClient:
    """
    Async Redis client with support for both local Redis and LangCache cloud.

    Supports:
    - Key-value caching
    - Pub/Sub messaging
    - Rate limiting counters
    - Agent state management
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
        db: int = 0,
        use_langcache: bool = False,
    ):
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", 6379))
        self.password = password or os.getenv("REDIS_PASSWORD")
        self.db = db
        self.use_langcache = use_langcache

        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._pubsub: Optional[redis.client.PubSub] = None

        # LangCache configuration
        self.langcache_url = os.getenv("CACHE_URL")
        self.langcache_api_key = os.getenv("LANG_CACHE_API_KEY")
        self.cache_id = os.getenv("CACHE_ID")

    async def connect(self) -> None:
        """Establish connection to Redis."""
        try:
            if self.use_langcache and self.langcache_url:
                # Connect to LangCache cloud
                self._pool = ConnectionPool.from_url(
                    f"rediss://{self.langcache_url}",
                    password=self.langcache_api_key,
                    decode_responses=True,
                    max_connections=20,
                )
                logger.info("connecting_to_langcache", url=self.langcache_url)
            else:
                # Connect to local Redis
                self._pool = ConnectionPool(
                    host=self.host,
                    port=self.port,
                    password=self.password,
                    db=self.db,
                    decode_responses=True,
                    max_connections=20,
                )
                logger.info("connecting_to_redis", host=self.host, port=self.port)

            self._client = redis.Redis(connection_pool=self._pool)

            # Test connection
            await self._client.ping()
            logger.info("redis_connected")

        except Exception as e:
            logger.error("redis_connection_failed", error=str(e))
            raise

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self._pubsub:
            await self._pubsub.close()
        if self._client:
            await self._client.close()
        if self._pool:
            await self._pool.disconnect()
        logger.info("redis_disconnected")

    @asynccontextmanager
    async def get_connection(self):
        """Context manager for Redis connection."""
        if not self._client:
            await self.connect()
        try:
            yield self._client
        finally:
            pass  # Connection pooling handles cleanup

    # =========================================================================
    # Key-Value Operations
    # =========================================================================

    async def get(self, key: str) -> Optional[str]:
        """Get value by key."""
        async with self.get_connection() as client:
            return await client.get(key)

    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
    ) -> bool:
        """Set key-value with optional expiration (seconds)."""
        async with self.get_connection() as client:
            return await client.set(key, value, ex=expire)

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        async with self.get_connection() as client:
            return await client.delete(*keys)

    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        async with self.get_connection() as client:
            return await client.exists(key) > 0

    async def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on key."""
        async with self.get_connection() as client:
            return await client.expire(key, seconds)

    async def ttl(self, key: str) -> int:
        """Get time to live for key."""
        async with self.get_connection() as client:
            return await client.ttl(key)

    # =========================================================================
    # Hash Operations (for structured data)
    # =========================================================================

    async def hget(self, name: str, key: str) -> Optional[str]:
        """Get hash field value."""
        async with self.get_connection() as client:
            return await client.hget(name, key)

    async def hset(self, name: str, key: str, value: Any) -> int:
        """Set hash field value."""
        async with self.get_connection() as client:
            return await client.hset(name, key, value)

    async def hgetall(self, name: str) -> dict:
        """Get all hash fields and values."""
        async with self.get_connection() as client:
            return await client.hgetall(name)

    async def hdel(self, name: str, *keys: str) -> int:
        """Delete hash fields."""
        async with self.get_connection() as client:
            return await client.hdel(name, *keys)

    # =========================================================================
    # List Operations (for queues)
    # =========================================================================

    async def lpush(self, key: str, *values: Any) -> int:
        """Push values to list head."""
        async with self.get_connection() as client:
            return await client.lpush(key, *values)

    async def rpush(self, key: str, *values: Any) -> int:
        """Push values to list tail."""
        async with self.get_connection() as client:
            return await client.rpush(key, *values)

    async def lpop(self, key: str) -> Optional[str]:
        """Pop value from list head."""
        async with self.get_connection() as client:
            return await client.lpop(key)

    async def rpop(self, key: str) -> Optional[str]:
        """Pop value from list tail."""
        async with self.get_connection() as client:
            return await client.rpop(key)

    async def lrange(self, key: str, start: int, end: int) -> list:
        """Get list range."""
        async with self.get_connection() as client:
            return await client.lrange(key, start, end)

    async def llen(self, key: str) -> int:
        """Get list length."""
        async with self.get_connection() as client:
            return await client.llen(key)

    # =========================================================================
    # Set Operations (for unique collections)
    # =========================================================================

    async def sadd(self, key: str, *values: Any) -> int:
        """Add members to set."""
        async with self.get_connection() as client:
            return await client.sadd(key, *values)

    async def srem(self, key: str, *values: Any) -> int:
        """Remove members from set."""
        async with self.get_connection() as client:
            return await client.srem(key, *values)

    async def smembers(self, key: str) -> set:
        """Get all set members."""
        async with self.get_connection() as client:
            return await client.smembers(key)

    async def sismember(self, key: str, value: Any) -> bool:
        """Check if value is set member."""
        async with self.get_connection() as client:
            return await client.sismember(key, value)

    # =========================================================================
    # Sorted Set Operations (for ranked data)
    # =========================================================================

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        """Add members with scores to sorted set."""
        async with self.get_connection() as client:
            return await client.zadd(key, mapping)

    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        withscores: bool = False,
    ) -> list:
        """Get sorted set range by index."""
        async with self.get_connection() as client:
            return await client.zrange(key, start, end, withscores=withscores)

    async def zrangebyscore(
        self,
        key: str,
        min_score: float,
        max_score: float,
        withscores: bool = False,
    ) -> list:
        """Get sorted set range by score."""
        async with self.get_connection() as client:
            return await client.zrangebyscore(
                key, min_score, max_score, withscores=withscores
            )

    # =========================================================================
    # Pub/Sub Operations
    # =========================================================================

    async def publish(self, channel: str, message: str) -> int:
        """Publish message to channel."""
        async with self.get_connection() as client:
            return await client.publish(channel, message)

    async def subscribe(self, *channels: str) -> redis.client.PubSub:
        """Subscribe to channels."""
        if not self._client:
            await self.connect()
        self._pubsub = self._client.pubsub()
        await self._pubsub.subscribe(*channels)
        return self._pubsub

    async def psubscribe(self, *patterns: str) -> redis.client.PubSub:
        """Subscribe to channel patterns."""
        if not self._client:
            await self.connect()
        self._pubsub = self._client.pubsub()
        await self._pubsub.psubscribe(*patterns)
        return self._pubsub

    # =========================================================================
    # Rate Limiting Operations
    # =========================================================================

    async def incr(self, key: str) -> int:
        """Increment key value."""
        async with self.get_connection() as client:
            return await client.incr(key)

    async def incrby(self, key: str, amount: int) -> int:
        """Increment key by amount."""
        async with self.get_connection() as client:
            return await client.incrby(key, amount)

    async def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check rate limit using sliding window.

        Returns:
            Tuple of (is_allowed, current_count)
        """
        async with self.get_connection() as client:
            current = await client.get(key)

            if current is None:
                await client.set(key, 1, ex=window_seconds)
                return True, 1

            count = int(current)
            if count >= max_requests:
                return False, count

            new_count = await client.incr(key)
            return True, new_count


# Singleton instance
_redis_client: Optional[RedisClient] = None


def get_redis_client(use_langcache: bool = False) -> RedisClient:
    """Get or create Redis client singleton."""
    global _redis_client
    if _redis_client is None:
        _redis_client = RedisClient(use_langcache=use_langcache)
    return _redis_client


async def init_redis(use_langcache: bool = False) -> RedisClient:
    """Initialize Redis client and establish connection."""
    client = get_redis_client(use_langcache)
    await client.connect()
    return client


async def close_redis() -> None:
    """Close Redis connection."""
    global _redis_client
    if _redis_client:
        await _redis_client.disconnect()
        _redis_client = None


def get_redis() -> Optional[RedisClient]:
    """Get the current Redis client (may be None if not initialized)."""
    return _redis_client
