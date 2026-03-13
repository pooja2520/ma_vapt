"""Pytest fixtures. Tests require MySQL with MYSQL_DATABASE from .env."""
import os
import pytest
from dotenv import load_dotenv

load_dotenv()

# Skip DB tests if MySQL not configured
MYSQL_DATABASE = os.environ.get('MYSQL_DATABASE', 'vapt_db')


def mysql_available():
    try:
        from db.queries import get_pool
        pool = get_pool()
        conn = pool.get_connection()
        conn.close()
        return True
    except Exception:
        return False


@pytest.fixture(scope='session')
def app():
    """Flask app for testing."""
    from app import app
    return app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Flask CLI runner."""
    return app.test_cli_runner()


@pytest.fixture
def db_conn():
    """Database connection for tests. Skips if MySQL unavailable."""
    if not mysql_available():
        pytest.skip("MySQL not available")
    from db.queries import get_pool
    conn = get_pool().get_connection()
    yield conn
    conn.close()
