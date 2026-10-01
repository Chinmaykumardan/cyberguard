"""
HoneyShield Database Access Layer
Implements thread-safe MySQL connection pooling using PyMySQL and DBUtils PooledDB.
Enforces parameterized queries across all database operations.
"""
import logging
import os
import pymysql
from pymysql.cursors import DictCursor
from dbutils.pooled_db import PooledDB
from config import Config

logger = logging.getLogger("honeyshield.db")

_pool = None


def get_pool():
    """Initializes or retrieves the singleton PyMySQL connection pool."""
    global _pool
    if _pool is None:
        connect_kwargs = {
            "creator": pymysql,
            "mincached": Config.DB_POOL_MIN,
            "maxcached": Config.DB_POOL_MAX,
            "maxconnections": Config.DB_POOL_MAX,
            "blocking": True,
            "maxusage": None,
            "setsession": [],
            "reset": True,
            "user": Config.DB_USER,
            "password": Config.DB_PASSWORD,
            "database": Config.DB_NAME,
            "charset": "utf8mb4",
            "cursorclass": DictCursor,
            "autocommit": True,
            "connect_timeout": 10,
        }

        # Check for unix socket fallback if on localhost
        unix_socket = "/var/run/mysqld/mysqld.sock"
        if os.path.exists(unix_socket) and Config.DB_HOST in ("localhost", "127.0.0.1") and not Config.DB_PASSWORD:
            connect_kwargs["unix_socket"] = unix_socket
        else:
            connect_kwargs["host"] = Config.DB_HOST
            connect_kwargs["port"] = Config.DB_PORT

        try:
            _pool = PooledDB(**connect_kwargs)
            logger.info("PyMySQL connection pool initialized successfully.")
        except Exception as e:
            # Fallback to host/port if socket failed or vice versa
            if "unix_socket" in connect_kwargs:
                del connect_kwargs["unix_socket"]
                connect_kwargs["host"] = Config.DB_HOST
                connect_kwargs["port"] = Config.DB_PORT
                _pool = PooledDB(**connect_kwargs)
            else:
                logger.error("Failed to initialize PyMySQL connection pool: %s", e)
                raise
    return _pool


def get_db():
    """Acquires a dedicated connection from the connection pool."""
    pool = get_pool()
    return pool.connection()


def query_one(sql, params=None):
    """
    Executes a parameterized SQL query and returns a single row dictionary or None.
    """
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, params or ())
            return cursor.fetchone()
    finally:
        conn.close()


def query_all(sql, params=None):
    """
    Executes a parameterized SQL query and returns a list of row dictionaries.
    """
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, params or ())
            return cursor.fetchall()
    finally:
        conn.close()


def execute(sql, params=None):
    """
    Executes a parameterized INSERT, UPDATE, or DELETE query.
    Returns a tuple of (lastrowid, rowcount).
    """
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            count = cursor.execute(sql, params or ())
            return cursor.lastrowid, count
    finally:
        conn.close()


def init_db(schema_file="schema.sql"):
    """
    Bootstraps the database schema from schema.sql if tables do not exist.
    """
    if not os.path.exists(schema_file):
        logger.warning("Schema file %s not found. Skipping init_db.", schema_file)
        return

    with open(schema_file, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    # Split by semicolon, filtering out empty statements
    statements = [stmt.strip() for stmt in schema_sql.split(";") if stmt.strip()]

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            for statement in statements:
                clean_stmt = "\n".join(
                    line for line in statement.splitlines()
                    if not line.strip().startswith("--")
                ).strip()
                if clean_stmt:
                    cursor.execute(clean_stmt)
        logger.info("Database schema initialized successfully.")
    except Exception as e:
        logger.error("Error executing schema statements: %s", e)
        raise
    finally:
        conn.close()
