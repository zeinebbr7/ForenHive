"""
Shared PostgreSQL connection pool for forensic-engine modules.

The legacy modules use the pattern `conn = _pg_conn(); ... conn.close()` and
also `with _pg_conn() as conn: ...` (psycopg2's transaction context). To migrate
to a pool without rewriting every call site, `pooled_conn()` returns a thin
proxy that:
  • forwards every attribute (cursor, commit, rollback, …) to the real conn
  • releases the conn to the pool on `.close()`
  • supports `with proxy as c:` by entering the underlying conn's transaction
    context AND releasing the conn back to the pool on exit
"""

import os
import threading
import psycopg2
import psycopg2.pool

import config

_pool = None
_lock = threading.Lock()


def _build_pool():
    return psycopg2.pool.ThreadedConnectionPool(
        minconn=1,
        maxconn=10,
        host=config.PG_HOST,
        port=config.PG_PORT,
        dbname=config.PG_DB,
        user=config.PG_USER,
        password=os.environ.get("PG_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", ""),
    )


def _ensure_pool():
    global _pool
    if _pool is None:
        with _lock:
            if _pool is None:
                _pool = _build_pool()
    return _pool


def get_conn():
    return _ensure_pool().getconn()


def put_conn(conn):
    if _pool is not None and conn is not None:
        try:
            _pool.putconn(conn)
        except Exception:
            try:
                conn.close()
            except Exception:
                pass


def closeall():
    global _pool
    if _pool is not None:
        try:
            _pool.closeall()
        finally:
            _pool = None


class _PooledConnProxy:
    """Transparent proxy: behaves like a psycopg2 connection but releases to pool."""

    __slots__ = ("_conn", "_released")

    def __init__(self, conn):
        object.__setattr__(self, "_conn", conn)
        object.__setattr__(self, "_released", False)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        if name in self.__slots__:
            object.__setattr__(self, name, value)
        else:
            setattr(self._conn, name, value)

    def close(self):
        if not self._released:
            object.__setattr__(self, "_released", True)
            put_conn(self._conn)

    def __enter__(self):
        # psycopg2 connection __enter__ returns the connection itself (transaction ctx)
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._conn.__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def pooled_conn():
    """Return a pooled connection proxy with transparent .close() and `with` support."""
    return _PooledConnProxy(get_conn())
