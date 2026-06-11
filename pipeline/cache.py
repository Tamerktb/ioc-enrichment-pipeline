"""
Cache Layer — SQLite-backed cache for enrichment results.

Demonstrates:
- Reliability Engineering (cache prevents redundant API calls, saves quota)
- System Design (separation of cache from enrichment logic)
- TTL management per IOC type
"""

import sqlite3
import json
import hashlib
import time
import os
from typing import Optional
from pathlib import Path


class EnrichmentCache:
    """
    SQLite-backed cache for IOC enrichment results.

    Features:
    - Per-IOC-type TTL (IPs change faster than file hashes)
    - Automatic cleanup of expired entries
    - Cache hit/miss tracking
    - MD5 hashing of IOC value for consistent keys
    """

    def __init__(self, db_path: str = "pipeline_cache.db", default_ttl: int = 3600, ttl_by_type: Optional[dict] = None):
        self.db_path = str(Path(db_path).resolve())
        self.default_ttl = default_ttl
        self.ttl_by_type = ttl_by_type or {}
        self._stats = {"hits": 0, "misses": 0, "stale": 0}
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-safe connection to the cache database."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent access
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        """Initialize the cache schema."""
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    cache_key TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    result TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_expires
                ON enrichment_cache(expires_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_ioc
                ON enrichment_cache(ioc_type, ioc_value)
            """)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _make_cache_key(ioc_type: str, ioc_value: str, tool_name: str) -> str:
        """Generate a deterministic cache key from IOC + tool."""
        raw = f"{ioc_type}:{ioc_value.strip().lower()}:{tool_name}"
        return hashlib.md5(raw.encode()).hexdigest()

    def _get_ttl(self, ioc_type: str) -> int:
        """Get TTL for a specific IOC type, falling back to default."""
        return self.ttl_by_type.get(ioc_type.lower(), self.default_ttl)

    def get(self, ioc_type: str, ioc_value: str, tool_name: str) -> Optional[dict]:
        """
        Retrieve a cached enrichment result.
        Returns None if not found or expired.
        """
        cache_key = self._make_cache_key(ioc_type, ioc_value, tool_name)
        now = time.time()

        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT result, expires_at FROM enrichment_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()

            if row is None:
                self._stats["misses"] += 1
                return None

            if now > row["expires_at"]:
                # Entry expired — delete it
                conn.execute("DELETE FROM enrichment_cache WHERE cache_key = ?", (cache_key,))
                conn.commit()
                self._stats["stale"] += 1
                return None

            self._stats["hits"] += 1
            return json.loads(row["result"])
        finally:
            conn.close()

    def set(self, ioc_type: str, ioc_value: str, tool_name: str, result: dict):
        """
        Store an enrichment result in the cache.
        """
        cache_key = self._make_cache_key(ioc_type, ioc_value, tool_name)
        now = time.time()
        ttl = self._get_ttl(ioc_type)

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO enrichment_cache
                   (cache_key, ioc_type, ioc_value, tool_name, result, cached_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (cache_key, ioc_type.lower(), ioc_value.strip(),
                 tool_name, json.dumps(result), now, now + ttl)
            )
            conn.commit()
        finally:
            conn.close()

    def get_cache_for_ioc(self, ioc_type: str, ioc_value: str) -> dict:
        """
        Get all cached results for a specific IOC across all tools.
        Returns a dict of {tool_name: result}
        """
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT tool_name, result FROM enrichment_cache "
                "WHERE ioc_type = ? AND ioc_value = ? AND expires_at > ?",
                (ioc_type.lower(), ioc_value.strip(), time.time())
            ).fetchall()
            return {row["tool_name"]: json.loads(row["result"]) for row in rows}
        finally:
            conn.close()

    def clean_expired(self) -> int:
        """Remove all expired cache entries. Returns count of removed entries."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM enrichment_cache WHERE expires_at < ?",
                (time.time(),)
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def stats(self) -> dict:
        """Get cache statistics."""
        conn = self._get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) FROM enrichment_cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM enrichment_cache WHERE expires_at < ?",
                (time.time(),)
            ).fetchone()[0]
            return {
                "total_entries": total,
                "expired_entries": expired,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "stale": self._stats["stale"],
                "hit_rate": self._stats["hits"] / max(self._stats["hits"] + self._stats["misses"], 1),
                "db_path": self.db_path,
            }
        finally:
            conn.close()

    def clear(self):
        """Clear all cache entries."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM enrichment_cache")
            conn.commit()
        finally:
            conn.close()
            self._stats = {"hits": 0, "misses": 0, "stale": 0}