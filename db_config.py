import os
import socket
import psycopg2
import logging
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def detect_host():
    """
    Detect whether we are running inside Docker Compose or on K8s.
    - In Docker Compose: DB_HOST resolves to 'db'
    - In K8s: DB_HOST is 'db' service (ClusterIP)
    - If nothing resolves, fallback → localhost
    """
    db_host = os.getenv("DB_HOST")
    if db_host:
        return db_host

    try:
        socket.gethostbyname("db")
        return "db"
    except socket.gaierror:
        return "localhost"


def parse_database_url(db_url: str):
    """Parse DATABASE_URL into connection params dict"""
    result = urlparse(db_url)
    return {
        "dbname": result.path.lstrip("/"),
        "user": result.username,
        "password": result.password,
        "host": result.hostname,
        "port": result.port or 5432
    }


def get_connection(db_key="default"):
    """
    Returns a psycopg2 connection.
    - Prefers DATABASE_URL if set.
    - Otherwise falls back to split env vars.
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        try:
            config = parse_database_url(db_url)
            logging.info(f"Connecting via DATABASE_URL → host={config['host']}, port={config['port']}, db={config['dbname']}")
            return psycopg2.connect(**config)
        except Exception as e:
            logging.error(f"❌ Failed to use DATABASE_URL: {db_url}, error={e}")
            raise

    # Fallback configs
    DATABASES = {
        "default": {
            "dbname": os.getenv("DB_NAME", "packetdb"),
            "user": os.getenv("DB_USER", "packetuser"),
            "password": os.getenv("DB_PASS", "packetpass"),
            "host": detect_host(),
            "port": int(os.getenv("DB_PORT", "5432")),
        },
        "admin_db": {
            "dbname": os.getenv("ADMIN_DB_NAME", "packets"),
            "user": os.getenv("ADMIN_DB_USER", "admin"),
            "password": os.getenv("ADMIN_DB_PASS", "secret"),
            "host": detect_host(),
            "port": int(os.getenv("DB_PORT", "5432")),
        }
    }

    config = DATABASES[db_key]
    logging.info(f"Connecting via split vars → host={config['host']}, port={config['port']}, db={config['dbname']}")
    return psycopg2.connect(**config)
