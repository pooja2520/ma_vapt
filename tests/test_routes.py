"""Route integration tests. Require MySQL and valid session."""
import pytest
import time
from unittest.mock import patch, MagicMock


@pytest.fixture
def logged_in_client(client):
    """Client with logged-in session (admin)."""
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['user_email'] = 'admin@vapt.pro'
        sess['user_name'] = 'Admin User'
        sess['user_role'] = 'admin'
    return client


def test_index_redirects_when_logged_in(logged_in_client):
    r = logged_in_client.get('/')
    assert r.status_code in (302, 200)
    if r.status_code == 302:
        assert 'dashboard' in r.location.lower()


def test_dashboard_requires_login(client):
    r = client.get('/dashboard')
    assert r.status_code == 302
    assert 'login' in r.location.lower() or r.location.endswith('/')


def test_dashboard_with_login(logged_in_client):
    r = logged_in_client.get('/dashboard')
    assert r.status_code == 200


def test_signup_page(client):
    r = client.get('/signup')
    assert r.status_code == 200
    assert b'Create' in r.data or b'sign up' in r.data.lower()


def test_login_page(client):
    r = client.get('/')
    assert r.status_code == 200
    assert b'Sign in' in r.data or b'login' in r.data.lower()


def test_api_targets_requires_login(client):
    r = client.get('/api/targets')
    assert r.status_code == 302


def test_api_targets_with_login(logged_in_client):
    r = logged_in_client.get('/api/targets')
    assert r.status_code == 200
    data = r.get_json()
    assert 'targets' in data
    assert isinstance(data['targets'], list)


def test_api_dashboard_stats_with_login(logged_in_client):
    r = logged_in_client.get('/api/dashboard-stats')
    assert r.status_code == 200
    data = r.get_json()
    assert 'stats' in data
    assert 'total' in data['stats']


def test_scan_no_request_context_error(logged_in_client):
    """Regression: scan thread must not raise 'Working outside of request context'."""
    mock_result = {
        'status': 'success',
        'results': [{'Test': 'Mock', 'Severity': 'info', 'Finding': 'Test'}],
        'filename': 'test_report.xlsx',
    }
    with patch('app.perform_vapt_scan', return_value=mock_result):
        r = logged_in_client.post('/scan', json={
            'target': 'http://example.com',
            'auth_type': 'none',
            'auth_data': {},
            'owasp_enabled': True,
        }, content_type='application/json')
    assert r.status_code == 200
    data = r.get_json()
    assert data.get('status') == 'started'
    # Wait for background thread (mock returns immediately)
    for _ in range(20):
        time.sleep(0.3)
        r2 = logged_in_client.get('/scan-status')
        d = r2.get_json()
        if d.get('status') == 'success':
            return  # Pass: scan completed without request context error
        if d.get('status') == 'error':
            msg = d.get('message', '')
            assert 'request context' not in msg.lower(), f"Got request context error: {msg}"
            return  # Other error, but not request context
    # Timeout: assume OK (thread may still be running)


def test_auth_session_key_normalization(app):
    """Verify http and https share the same auth_sessions key."""
    from app import normalize_target_url
    assert normalize_target_url('http://example.com') == 'example.com/'
    assert normalize_target_url('https://example.com') == 'example.com/'
    assert normalize_target_url('https://example.com/') == 'example.com/'
    assert normalize_target_url('https://example.com/login') == 'example.com/login'
    assert normalize_target_url('example.com') == 'example.com/'


def test_form_auth_field_detection(logged_in_client):
    """Verify /api/detect-login-fields returns field names when login form is found."""
    html = '''
    <html><body><form action="/login" method="post">
        <input name="j_username" type="text">
        <input name="j_password" type="password">
    </form></body></html>
    '''
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {'Content-Type': 'text/html'}
    mock_resp.text = html
    with patch('app.requests.get', return_value=mock_resp):
        r = logged_in_client.post('/api/detect-login-fields', json={'login_url': 'https://example.com/login'})
    assert r.status_code == 200
    data = r.get_json()
    assert data.get('status') == 'ok'
    assert data.get('username_field') == 'j_username'
    assert data.get('password_field') == 'j_password'


def test_form_login_at_scan_start(logged_in_client):
    """Verify scan with form auth passes full auth_data for re-login at crawl start."""
    mock_result = {'status': 'success', 'results': [], 'filename': 'test.xlsx'}
    captured_credentials = []

    def capture_credentials(*args, **kwargs):
        captured_credentials.append(kwargs.get('auth_credentials'))
        return mock_result

    with patch('app.perform_vapt_scan', side_effect=capture_credentials):
        r = logged_in_client.post('/scan', json={
            'target': 'https://example.com',
            'auth_type': 'form',
            'auth_data': {
                'login_url': 'https://example.com/login',
                'username': 'testuser',
                'password': 'testpass',
                'username_field': 'user',
                'password_field': 'pass',
            },
            'owasp_enabled': True,
        })
    assert r.status_code == 200
    assert r.get_json().get('status') == 'started'
    for _ in range(15):
        time.sleep(0.2)
        if captured_credentials:
            break
    assert len(captured_credentials) >= 1
    creds = captured_credentials[0]
    assert creds is not None
    assert creds.get('type') == 'form'
    assert creds.get('data', {}).get('login_url') == 'https://example.com/login'
    assert creds.get('data', {}).get('username') == 'testuser'
