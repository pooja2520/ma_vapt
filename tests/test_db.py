"""Database layer tests. Require MySQL running with .env configured."""
import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture(autouse=True)
def skip_if_no_mysql():
    try:
        from db.queries import get_pool
        pool = get_pool()
        conn = pool.get_connection()
        conn.close()
    except Exception:
        pytest.skip("MySQL not available")


def test_get_user_by_email():
    from db import get_user_by_email
    user = get_user_by_email('admin@vapt.pro')
    assert user is not None
    assert user['email'] == 'admin@vapt.pro'
    assert 'password_hash' in user


def test_create_user_duplicate():
    from db import create_user, get_user_by_email
    # Admin exists from seed
    user = create_user('admin@vapt.pro', 'Admin', 'hash', 'admin')
    assert user is None


def test_create_and_get_user():
    from db import create_user, get_user_by_email
    import uuid
    email = f"test_{uuid.uuid4().hex[:8]}@test.com"
    user = create_user(email, 'Test User', generate_password_hash('test123'), 'user')
    assert user is not None
    assert user['email'] == email
    fetched = get_user_by_email(email)
    assert fetched is not None
    assert fetched['name'] == 'Test User'


def test_get_all_targets():
    from db import get_all_targets
    targets = get_all_targets(1)
    assert isinstance(targets, list)


def test_get_or_create_target():
    from db import get_or_create_target, get_target_by_id
    t = get_or_create_target('https://example-test-123.com', 1, name='Example', description='Test')
    assert t is not None
    assert t['url'] == 'https://example-test-123.com'
    assert t['name'] == 'Example'
    tid = t['id']
    t2 = get_target_by_id(tid, 1)
    assert t2['id'] == tid


def test_get_dashboard_stats():
    from db import get_dashboard_stats
    stats = get_dashboard_stats(1)
    assert 'total' in stats
    assert 'critical' in stats
    assert 'high' in stats
    assert isinstance(stats['total'], (int, type(None)))


def test_get_reports():
    from db import get_reports
    reports = get_reports(1)
    assert isinstance(reports, list)
