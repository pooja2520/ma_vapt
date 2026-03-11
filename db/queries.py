"""Database query helpers. All queries use parameterized statements for SQL injection safety."""
import json
from contextlib import contextmanager
from .config import get_db_config

_pool = None


def get_pool():
    """Get or create connection pool."""
    global _pool
    if _pool is None:
        import mysql.connector.pooling
        cfg = get_db_config()
        _pool = mysql.connector.pooling.MySQLConnectionPool(**cfg)
    return _pool


@contextmanager
def get_connection():
    """Context manager for DB connection."""
    conn = get_pool().get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_user_by_email(email):
    """Get user by email. Returns dict or None."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, email, name, first_name, last_name, organization, role, job_title, country,
                   experience_level, referral_source, bio, password_hash
            FROM users WHERE email = %s
        """, (email,))
        return cur.fetchone()


def create_user(
    email,
    name,
    password_hash,
    role='user',
    first_name=None,
    last_name=None,
    organization=None,
    job_title=None,
    country=None,
    experience_level=None,
    referral_source=None,
    bio=None,
):
    """Create a new user. Returns new user dict or None on duplicate email."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        try:
            cur.execute("""
                INSERT INTO users (
                    email, name, password_hash, role,
                    first_name, last_name, organization, job_title, country,
                    experience_level, referral_source, bio
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                email, name, password_hash, role,
                first_name or None, last_name or None, organization or None,
                job_title or None, country or None, experience_level or None,
                referral_source or None, bio or None,
            ))
            uid = cur.lastrowid
            return {
                'id': uid, 'email': email, 'name': name, 'password_hash': password_hash, 'role': role,
                'first_name': first_name, 'last_name': last_name, 'organization': organization,
                'job_title': job_title, 'country': country, 'experience_level': experience_level,
                'referral_source': referral_source, 'bio': bio,
            }
        except Exception as e:
            if 'Duplicate' in str(e) or 1062 in (e.errno if hasattr(e, 'errno') else []):
                return None
            raise


def save_signup_otp(email, otp_hash, expires_at):
    """Store or replace OTP for signup verification. email is normalized (lower). Returns rowcount or 0 on error."""
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO signup_otps (email, otp_hash, expires_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE otp_hash = VALUES(otp_hash), expires_at = VALUES(expires_at)
                """,
                (email, otp_hash, expires_at),
            )
            rowcount = cur.rowcount
        # Context exits here, commit is called BEFORE we return
        return rowcount
    except Exception as e:
        print(f"[ERROR] save_signup_otp failed: {e}")
        return 0


def verify_signup_otp(email, otp_plain):
    """Verify OTP for email. Returns True if valid and not expired."""
    from werkzeug.security import check_password_hash
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT otp_hash, expires_at FROM signup_otps WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
    if not row:
        return False
    from datetime import datetime
    if datetime.utcnow() > row['expires_at']:
        return False
    return check_password_hash(row['otp_hash'], otp_plain)


def delete_signup_otp(email):
    """Remove OTP record after successful signup."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM signup_otps WHERE email = %s", (email,))


def save_password_reset_otp(email, otp_hash, expires_at):
    """Store or replace OTP for password reset. email is normalized (lower). Returns rowcount or 0 on error."""
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO password_reset_otps (email, otp_hash, expires_at)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE otp_hash = VALUES(otp_hash), expires_at = VALUES(expires_at)
                """,
                (email, otp_hash, expires_at),
            )
            rowcount = cur.rowcount
        # Context exits here, commit is called BEFORE we return
        return rowcount
    except Exception as e:
        print(f"[ERROR] save_password_reset_otp failed: {e}")
        return 0


def verify_password_reset_otp(email, otp_plain):
    """Verify password reset OTP for email. Returns True if valid and not expired."""
    from werkzeug.security import check_password_hash
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT otp_hash, expires_at FROM password_reset_otps WHERE email = %s",
            (email,),
        )
        row = cur.fetchone()
    if not row:
        return False
    from datetime import datetime
    if datetime.utcnow() > row['expires_at']:
        return False
    return check_password_hash(row['otp_hash'], otp_plain)


def delete_password_reset_otp(email):
    """Remove password reset OTP after successful reset."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM password_reset_otps WHERE email = %s", (email,))


def update_user_password_by_email(email, password_hash):
    """Update password for user by email. Returns True if updated."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (password_hash, email))
        return cur.rowcount > 0


def get_all_targets(user_id):
    """Get all targets for a user."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, url, type, status, last_scan, scan_count, description,
                   total_vulns, vuln_counts_json, scan_config_json, created_at, updated_at
            FROM targets WHERE user_id = %s ORDER BY id
        """, (user_id,))
        rows = cur.fetchall()
    for r in rows:
        if r.get('vuln_counts_json'):
            try:
                r['vuln_counts'] = json.loads(r['vuln_counts_json'])
            except (json.JSONDecodeError, TypeError):
                r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        else:
            r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        if r.get('scan_config_json'):
            try:
                r['auth_config'] = json.loads(r['scan_config_json'])
            except (json.JSONDecodeError, TypeError):
                r['auth_config'] = {'type': 'none'}
        else:
            r['auth_config'] = {'type': 'none'}
        r['scan_history'] = []
    return rows


def get_target_by_id(target_id, user_id):
    """Get target by id for a user. Returns dict or None."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, url, type, status, last_scan, scan_count, description,
                   total_vulns, vuln_counts_json, scan_config_json
            FROM targets WHERE id = %s AND user_id = %s
        """, (target_id, user_id))
        r = cur.fetchone()
    if not r:
        return None
    if r.get('vuln_counts_json'):
        try:
            r['vuln_counts'] = json.loads(r['vuln_counts_json'])
        except (json.JSONDecodeError, TypeError):
            r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    else:
        r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    if r.get('scan_config_json'):
        try:
            r['auth_config'] = json.loads(r['scan_config_json'])
        except (json.JSONDecodeError, TypeError):
            r['auth_config'] = {'type': 'none'}
    else:
        r['auth_config'] = {'type': 'none'}
    r['scan_history'] = get_scan_history_for_target(target_id)
    return r


def get_target_by_url(url, user_id):
    """Get target by url for a user. Returns dict or None."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, url, type, status, last_scan, scan_count, description,
                   total_vulns, vuln_counts_json, scan_config_json
            FROM targets WHERE url = %s AND user_id = %s
        """, (url, user_id))
        r = cur.fetchone()
    if not r:
        return None
    if r.get('vuln_counts_json'):
        try:
            r['vuln_counts'] = json.loads(r['vuln_counts_json'])
        except (json.JSONDecodeError, TypeError):
            r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    else:
        r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    if r.get('scan_config_json'):
        try:
            r['auth_config'] = json.loads(r['scan_config_json'])
        except (json.JSONDecodeError, TypeError):
            r['auth_config'] = {'type': 'none'}
    else:
        r['auth_config'] = {'type': 'none'}
    r['scan_history'] = get_scan_history_for_target(r['id'])
    return r


def get_or_create_target(url, user_id, name=None, ttype=None, description='', scan_config=None):
    """Get existing target by URL for user or create new one. Returns target dict with id."""
    t = get_target_by_url(url, user_id)
    if t:
        return t
    if name is None:
        name = url.replace('https://', '').replace('http://', '').split('/')[0]
    if ttype is None:
        if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
            ttype = 'API'
        elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
            ttype = 'IP'
        else:
            ttype = 'Web'
    scan_config_json = json.dumps(scan_config) if scan_config else None
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            INSERT INTO targets (user_id, name, url, type, status, last_scan, scan_count, description, total_vulns, vuln_counts_json, scan_config_json)
            VALUES (%s, %s, %s, %s, 'Active', 'Never', 0, %s, 0, %s, %s)
        """, (user_id, name[:255], url[:2048], ttype, description or '', json.dumps({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}), scan_config_json))
        tid = cur.lastrowid
    return get_target_by_id(tid, user_id)


def update_target(target_id, user_id, **kwargs):
    """Update target fields. Valid keys: name, url, type, description, status, last_scan, scan_count, total_vulns, vuln_counts, scan_config."""
    allowed = {'name', 'url', 'type', 'description', 'status', 'last_scan', 'scan_count', 'total_vulns', 'vuln_counts', 'scan_config'}
    updates = []
    values = []
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k == 'vuln_counts':
            updates.append("vuln_counts_json = %s")
            values.append(json.dumps(v) if isinstance(v, dict) else v)
        elif k == 'scan_config':
            updates.append("scan_config_json = %s")
            values.append(json.dumps(v) if isinstance(v, dict) else v)
        else:
            updates.append(f"{k} = %s")
            if k == 'url':
                values.append((v or '')[:2048])
            elif k == 'name':
                values.append((v or '')[:255])
            else:
                values.append(v)
    if not updates:
        return
    values.extend([target_id, user_id])
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(f"UPDATE targets SET {', '.join(updates)} WHERE id = %s AND user_id = %s", values)


def delete_target(target_id, user_id):
    """Delete target for user (cascade to scan_history, vulnerabilities)."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM targets WHERE id = %s AND user_id = %s", (target_id, user_id))


def insert_scan_history(target_id, scan_time, total, critical, high, medium, low, info, report_filename, runtime_seconds):
    """Insert scan history entry."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scan_history (target_id, scan_time, total, critical, high, medium, low, info, report_filename, runtime_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (target_id, scan_time, total, critical, high, medium, low, info, (report_filename or '')[:512], runtime_seconds))


def get_scan_history_for_target(target_id, limit=20):
    """Get scan history for target, most recent first."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT scan_time, total, critical, high, medium, low, info, report_filename as report, runtime_seconds
            FROM scan_history WHERE target_id = %s ORDER BY id DESC LIMIT %s
        """, (target_id, limit))
        return cur.fetchall()


def insert_vulnerabilities(target_id, target_url, scan_date, vuln_list):
    """Bulk insert vulnerabilities. vuln_list: list of dicts with Test, Severity, Status, Finding, etc."""
    if not vuln_list:
        return
    rows = []
    for v in vuln_list:
        rows.append((
            target_id,
            target_url[:2048],
            scan_date,
            (v.get('Test') or '')[:255],
            (v.get('Severity') or '')[:50],
            (v.get('Status') or '')[:50],
            v.get('Finding') or '',
            v.get('Vulnerable Path') or '',
            v.get('Remediation') or '',
            v.get('Resolution Steps') or '',
            1 if v.get('_fixed') else 0,
        ))
    with get_connection() as conn:
        cur = conn.cursor()
        cur.executemany("""
            INSERT INTO vulnerabilities (target_id, target_url, scan_date, test, severity, status, finding, vulnerable_path, remediation, resolution_steps, is_fixed)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, rows)


def get_vulnerabilities(user_id, severity_filter=None, status_filter=None, search=None, target_url=None):
    """Get vulnerabilities for a user with optional filters."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        sql = """
            SELECT id, target_id, target_url, scan_date, test, severity, status, finding, vulnerable_path,
                   remediation, resolution_steps, is_fixed
            FROM vulnerabilities WHERE user_id = %s
        """
        params = [user_id]
        conditions = []
        if severity_filter and severity_filter != 'all':
            conditions.append("LOWER(severity) = %s")
            params.append(severity_filter.lower())
        if status_filter and status_filter not in ('all', ''):
            conditions.append("LOWER(status) = %s")
            params.append(status_filter.lower())
        if search:
            conditions.append("(LOWER(test) LIKE %s OR LOWER(finding) LIKE %s OR LOWER(target_url) LIKE %s)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if target_url:
            conditions.append("target_url = %s")
            params.append(target_url)
        if conditions:
            sql += " AND " + " AND ".join(conditions)
        sql += " ORDER BY id"
        cur.execute(sql, params)
        rows = cur.fetchall()
    result = []
    for r in rows:
        entry = {
            'id': r['id'],
            'Test': r['test'],
            'Severity': r['severity'],
            'Status': r['status'],
            'Finding': r['finding'],
            'Vulnerable Path': r['vulnerable_path'],
            'Remediation': r['remediation'],
            'Resolution Steps': r['resolution_steps'],
            'target_url': r['target_url'],
            'scan_date': r['scan_date'],
            '_fixed': bool(r['is_fixed']),
            '_display_status': 'Fixed' if r['is_fixed'] else (r['status'] or 'Open'),
        }
        result.append(entry)
    return result


def get_vulnerability_by_id(vuln_id, user_id):
    """Get single vulnerability by id for a user."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, target_id, target_url, scan_date, test, severity, status, finding, vulnerable_path,
                   remediation, resolution_steps, is_fixed
            FROM vulnerabilities WHERE id = %s AND user_id = %s
        """, (vuln_id, user_id))
        r = cur.fetchone()
    if not r:
        return None
    return {
        'id': r['id'],
        'Test': r['test'],
        'Severity': r['severity'],
        'Status': r['status'],
        'Finding': r['finding'],
        'Vulnerable Path': r['vulnerable_path'],
        'Remediation': r['remediation'],
        'Resolution Steps': r['resolution_steps'],
        'target_url': r['target_url'],
        'scan_date': r['scan_date'],
        '_fixed': bool(r['is_fixed']),
        '_display_status': 'Fixed' if r['is_fixed'] else (r['status'] or 'Open'),
    }


def get_vulnerabilities_by_target_url(target_url, user_id, limit=10):
    """Get recent vulnerabilities for a target URL for a user."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, test, severity, status, finding, vulnerable_path, is_fixed
            FROM vulnerabilities WHERE target_url = %s AND user_id = %s ORDER BY id DESC LIMIT %s
        """, (target_url, user_id, limit))
        rows = cur.fetchall()
    return [{
        'id': r['id'],
        'test': r['test'],
        'severity': r['severity'],
        'finding': r['finding'],
        'status': r['status'],
        'path': r['vulnerable_path'],
        '_display_status': 'Fixed' if r['is_fixed'] else (r['status'] or 'Open'),
    } for r in rows]


def toggle_vulnerability_fixed(vuln_id, user_id):
    """Toggle is_fixed for vulnerability. Returns (new_fixed, new_display_status)."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT is_fixed, status FROM vulnerabilities WHERE id = %s AND user_id = %s", (vuln_id, user_id))
        r = cur.fetchone()
        if not r:
            return None
        new_fixed = 0 if r['is_fixed'] else 1
        cur.execute("UPDATE vulnerabilities SET is_fixed = %s WHERE id = %s AND user_id = %s", (new_fixed, vuln_id, user_id))
        new_status = 'Fixed' if new_fixed else (r['status'] or 'Open')
        return (bool(new_fixed), new_status)


def get_dashboard_stats(user_id):
    """Get aggregated severity counts from vulnerabilities for a user."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) as medium,
                   SUM(CASE WHEN LOWER(severity) = 'low' THEN 1 ELSE 0 END) as low,
                   SUM(CASE WHEN LOWER(severity) = 'info' THEN 1 ELSE 0 END) as info
            FROM vulnerabilities WHERE user_id = %s
        """, (user_id,))
        r = cur.fetchone()
    return {
        'total': r['total'] or 0,
        'critical': r['critical'] or 0,
        'high': r['high'] or 0,
        'medium': r['medium'] or 0,
        'low': r['low'] or 0,
        'info': r['info'] or 0,
    }


def insert_report(user_id, name, target_url, filename, date, status, vuln_counts, total, runtime_seconds, scan_time):
    """Insert report for a user. Returns new report id."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO reports (user_id, name, target_url, filename, date, status, vuln_counts_json, total, runtime_seconds, scan_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, name[:255], target_url[:2048], filename[:512], date, status, json.dumps(vuln_counts), total, runtime_seconds, scan_time or date))
        return cur.lastrowid


def get_reports(user_id):
    """Get all reports for a user, most recent first."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, target_url, filename, date, status, vuln_counts_json, total, runtime_seconds, scan_time
            FROM reports WHERE user_id = %s ORDER BY id DESC
        """, (user_id,))
        rows = cur.fetchall()
    for r in rows:
        r['scan_time'] = r.get('scan_time') or r.get('date', '')
        if r.get('vuln_counts_json'):
            try:
                r['vuln_counts'] = json.loads(r['vuln_counts_json'])
            except (json.JSONDecodeError, TypeError):
                r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        else:
            r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    return rows


def get_report_by_id(report_id, user_id):
    """Get report by id for a user."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, name, target_url, filename, date, status, vuln_counts_json, total, runtime_seconds, scan_time
            FROM reports WHERE id = %s AND user_id = %s
        """, (report_id, user_id))
        r = cur.fetchone()
    if not r:
        return None
    r['scan_time'] = r.get('scan_time') or r.get('date', '')
    if r.get('vuln_counts_json'):
        try:
            r['vuln_counts'] = json.loads(r['vuln_counts_json'])
        except (json.JSONDecodeError, TypeError):
            r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    else:
        r['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    return r


def get_recent_vulnerabilities(user_id, limit=5):
    """Get most recent vulnerabilities for a user's dashboard."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, test, severity, status, finding, target_url
            FROM vulnerabilities WHERE user_id = %s ORDER BY id DESC LIMIT %s
        """, (user_id, limit))
        return cur.fetchall()


def scan_completion_transaction(target, raw_results, filename, scan_time, severity_counts_dict, runtime_seconds, user_id):
    """
    Execute scan completion in a single transaction for a user.
    """
    conn = get_pool().get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        # Get or create target for this user
        cur.execute("SELECT id, name, url FROM targets WHERE url = %s AND user_id = %s", (target, user_id))
        t = cur.fetchone()
        if t:
            tid = t['id']
            cur.execute("""
                UPDATE targets SET last_scan = %s, status = 'Active', scan_count = scan_count + 1,
                       total_vulns = %s, vuln_counts_json = %s
                WHERE id = %s
            """, (scan_time, len(raw_results), json.dumps(severity_counts_dict), tid))
        else:
            name = target.replace('https://', '').replace('http://', '').split('/')[0]
            if any(x in target for x in ['api.', '/api', '/rest', '/graphql']):
                ttype = 'API'
            elif any(target.startswith(p) for p in ['192.168.', '10.', '172.']):
                ttype = 'IP'
            else:
                ttype = 'Web'
            cur.execute("""
                INSERT INTO targets (user_id, name, url, type, status, last_scan, scan_count, description, total_vulns, vuln_counts_json)
                VALUES (%s, %s, %s, %s, 'Active', %s, 1, '', %s, %s)
            """, (user_id, name[:255], target[:2048], ttype, scan_time, len(raw_results), json.dumps(severity_counts_dict)))
            tid = cur.lastrowid

        # Insert scan history
        cur.execute("""
            INSERT INTO scan_history (target_id, scan_time, total, critical, high, medium, low, info, report_filename, runtime_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (tid, scan_time, len(raw_results),
              severity_counts_dict.get('critical', 0), severity_counts_dict.get('high', 0),
              severity_counts_dict.get('medium', 0), severity_counts_dict.get('low', 0),
              severity_counts_dict.get('info', 0), filename[:512], runtime_seconds))

        # Bulk insert vulnerabilities
        vuln_rows = []
        for v in raw_results:
            vuln_rows.append((
                user_id, tid, target[:2048], v.get('scan_date', scan_time),
                (v.get('Test') or '')[:255], (v.get('Severity') or '')[:50], (v.get('Status') or '')[:50],
                v.get('Finding') or '', v.get('Vulnerable Path') or '',
                v.get('Remediation') or '', v.get('Resolution Steps') or '',
                1 if v.get('_fixed') else 0,
            ))
        if vuln_rows:
            cur.executemany("""
                INSERT INTO vulnerabilities (user_id, target_id, target_url, scan_date, test, severity, status, finding, vulnerable_path, remediation, resolution_steps, is_fixed)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, vuln_rows)

        # Insert report
        target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
        cur.execute("""
            INSERT INTO reports (user_id, name, target_url, filename, date, status, vuln_counts_json, total, runtime_seconds, scan_time)
            VALUES (%s, %s, %s, %s, %s, 'Completed', %s, %s, %s, %s)
        """, (user_id, f"Full Security Scan – {target_name}", target[:2048], filename[:512],
              scan_time[:10], json.dumps(severity_counts_dict), len(raw_results), runtime_seconds, scan_time))

        conn.commit()
        return tid
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULED SCANS
# ══════════════════════════════════════════════════════════════════════════════

def _decode_schedule(r):
    """Decode auth_config_json and serialize datetime fields as local (IST) strings.

    MySQL DATETIME columns have no timezone info. Historically some rows were
    written with UTC values (via datetime.utcnow()), while newer rows use
    local time (datetime.now()). We detect old UTC rows by checking whether
    adding the local UTC offset brings the value closer to now — if so it was
    stored as UTC and we shift it to local time before returning.
    """
    if not r:
        return None
    if r.get('auth_config_json'):
        try:
            r['auth_config'] = json.loads(r['auth_config_json'])
        except (json.JSONDecodeError, TypeError):
            r['auth_config'] = {'type': 'none'}
    else:
        r['auth_config'] = {'type': 'none'}

    from datetime import datetime as _dt, timedelta as _td
    import time as _t

    # Local UTC offset in seconds (handles DST automatically)
    _offset_sec = -(_t.timezone if _t.localtime().tm_isdst == 0 else _t.altzone)
    _offset     = _td(seconds=_offset_sec)
    _now_local  = _dt.now()

    for _col in ('last_run_at', 'next_run_at', 'created_at', 'updated_at'):
        val = r.get(_col)
        if not isinstance(val, _dt):
            continue
        # If stored value is UTC, shifting it by the local offset brings it
        # closer to local-now than the raw value does → it was stored as UTC.
        shifted      = val + _offset
        diff_raw     = abs((_now_local - val).total_seconds())
        diff_shifted = abs((_now_local - shifted).total_seconds())
        use          = shifted if diff_shifted < diff_raw else val
        r[_col]      = use.strftime('%Y-%m-%d %H:%M:%S')

    return r


def create_scheduled_scan(user_id, name, target_url, frequency='daily', scan_time='02:00',
                           day_of_week=None, day_of_month=None, auth_type='none',
                           auth_config=None, timeout_minutes=30, notify_on_done=True,
                           target_id=None, next_run_at=None):
    """Insert a new scheduled scan for a user. Returns full schedule dict."""
    auth_config_json = json.dumps(auth_config) if auth_config else None
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            INSERT INTO scheduled_scans
                (user_id, target_id, name, target_url,
                 frequency, scan_time, day_of_week, day_of_month,
                 auth_type, auth_config_json,
                 timeout_minutes, notify_on_done, status, next_run_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'active', %s)
        """, (user_id, target_id, name[:255], target_url[:2048],
              frequency, scan_time, day_of_week, day_of_month,
              auth_type, auth_config_json,
              timeout_minutes, 1 if notify_on_done else 0, next_run_at))
        new_id = cur.lastrowid
    return get_scheduled_scan_by_id(new_id, user_id)


def get_scheduled_scan_by_id(schedule_id, user_id):
    """Fetch a single scheduled scan by id for a user. Returns dict or None."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, user_id, target_id, name, target_url,
                   frequency, scan_time, day_of_week, day_of_month,
                   auth_type, auth_config_json, timeout_minutes, notify_on_done,
                   status, run_count, last_run_at, next_run_at, created_at, updated_at
            FROM scheduled_scans WHERE id = %s AND user_id = %s
        """, (schedule_id, user_id))
        return _decode_schedule(cur.fetchone())


def get_all_scheduled_scans(user_id, status_filter=None):
    """Fetch all scheduled scans for a user, newest first. Optionally filter by status."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        if status_filter:
            cur.execute("""
                SELECT id, user_id, target_id, name, target_url,
                       frequency, scan_time, day_of_week, day_of_month,
                       auth_type, auth_config_json, timeout_minutes, notify_on_done,
                       status, run_count, last_run_at, next_run_at, created_at, updated_at
                FROM scheduled_scans WHERE user_id = %s AND status = %s ORDER BY id DESC
            """, (user_id, status_filter))
        else:
            cur.execute("""
                SELECT id, user_id, target_id, name, target_url,
                       frequency, scan_time, day_of_week, day_of_month,
                       auth_type, auth_config_json, timeout_minutes, notify_on_done,
                       status, run_count, last_run_at, next_run_at, created_at, updated_at
                FROM scheduled_scans WHERE user_id = %s ORDER BY id DESC
            """, (user_id,))
        return [_decode_schedule(r) for r in cur.fetchall()]


def update_scheduled_scan(schedule_id, user_id, **kwargs):
    """Update scheduled scan fields. Valid kwargs: name, target_url, target_id, frequency,
    scan_time, day_of_week, day_of_month, auth_type, auth_config, timeout_minutes,
    notify_on_done, status, next_run_at, last_run_at, run_count."""
    allowed = {'name', 'target_url', 'target_id', 'frequency', 'scan_time',
               'day_of_week', 'day_of_month', 'auth_type', 'auth_config',
               'timeout_minutes', 'notify_on_done', 'status',
               'next_run_at', 'last_run_at', 'run_count'}
    updates, values = [], []
    for k, v in kwargs.items():
        if k not in allowed:
            continue
        if k == 'auth_config':
            updates.append("auth_config_json = %s")
            values.append(json.dumps(v) if isinstance(v, dict) else v)
        elif k == 'notify_on_done':
            updates.append("notify_on_done = %s")
            values.append(1 if v else 0)
        elif k == 'target_url':
            updates.append("target_url = %s")
            values.append((v or '')[:2048])
        elif k == 'name':
            updates.append("name = %s")
            values.append((v or '')[:255])
        else:
            updates.append(f"{k} = %s")
            values.append(v)
    if not updates:
        return
    values.extend([schedule_id, user_id])
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            f"UPDATE scheduled_scans SET {', '.join(updates)} WHERE id = %s AND user_id = %s",
            values)


def delete_scheduled_scan(schedule_id, user_id):
    """Hard-delete a schedule (cascades to runs and tracked vulns). Returns True if deleted."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM scheduled_scans WHERE id = %s AND user_id = %s",
                    (schedule_id, user_id))
        return cur.rowcount > 0


def toggle_scheduled_scan_status(schedule_id, user_id):
    """Toggle active <-> paused. Returns new status string or None if not found."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT status FROM scheduled_scans WHERE id = %s AND user_id = %s",
                    (schedule_id, user_id))
        r = cur.fetchone()
        if not r:
            return None
        new_status = 'paused' if r['status'] == 'active' else 'active'
        cur.execute("UPDATE scheduled_scans SET status = %s WHERE id = %s AND user_id = %s",
                    (new_status, schedule_id, user_id))
    return new_status


def get_due_scheduled_scans(now=None):
    """Return all active schedules whose next_run_at <= now (all users). Used by scheduler."""
    from datetime import datetime
    if now is None:
        now = datetime.now()  # local time matches next_run_at storage
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, user_id, target_id, name, target_url,
                   frequency, scan_time, day_of_week, day_of_month,
                   auth_type, auth_config_json, timeout_minutes, notify_on_done,
                   status, run_count, last_run_at, next_run_at, created_at, updated_at
            FROM scheduled_scans
            WHERE status = 'active' AND next_run_at IS NOT NULL AND next_run_at <= %s
            ORDER BY next_run_at ASC
        """, (now,))
        return [_decode_schedule(r) for r in cur.fetchall()]


def mark_scheduled_scan_running(schedule_id):
    """Set scheduled scan status to 'running'. Called just before the scan fires."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE scheduled_scans SET status = 'running' WHERE id = %s", (schedule_id,))


# ── Scheduled Scan Runs ───────────────────────────────────────────────────────

def create_scheduled_scan_run(scheduled_scan_id, user_id, target_url, started_at=None):
    """Open a pending run record. Returns the new run id."""
    from datetime import datetime
    if started_at is None:
        started_at = datetime.now()  # local time, not UTC
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scheduled_scan_runs
                (scheduled_scan_id, user_id, target_url, started_at, result)
            VALUES (%s, %s, %s, %s, 'pending')
        """, (scheduled_scan_id, user_id, target_url[:2048], started_at))
        return cur.lastrowid


def complete_scheduled_scan_run(run_id, finished_at, duration_seconds, result,
                                 total_findings, severity_counts,
                                 report_filename=None, error_message=None):
    """Mark a run as finished with final severity counts."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE scheduled_scan_runs
            SET finished_at = %s, duration_seconds = %s, result = %s,
                total_findings = %s,
                critical = %s, high = %s, medium = %s, low = %s, info = %s,
                report_filename = %s, error_message = %s
            WHERE id = %s
        """, (finished_at, duration_seconds, result, total_findings,
              severity_counts.get('critical', 0), severity_counts.get('high', 0),
              severity_counts.get('medium', 0), severity_counts.get('low', 0),
              severity_counts.get('info', 0),
              (report_filename or '')[:512], error_message, run_id))


def finish_scheduled_scan(schedule_id, next_run_at, new_status='active'):
    """After a run completes: reset status, bump run_count, update last/next run timestamps."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE scheduled_scans
            SET status = %s, last_run_at = NOW(), next_run_at = %s, run_count = run_count + 1
            WHERE id = %s
        """, (new_status, next_run_at, schedule_id))


def get_run_history(user_id, schedule_id=None, limit=50):
    """Return run history for a user, optionally filtered to one schedule. Most recent first."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        if schedule_id:
            cur.execute("""
                SELECT r.id, r.scheduled_scan_id, s.name AS schedule_name,
                       r.target_url, r.started_at, r.finished_at, r.duration_seconds,
                       r.result, r.total_findings, r.critical, r.high, r.medium, r.low, r.info,
                       r.report_filename
                FROM scheduled_scan_runs r
                JOIN scheduled_scans s ON s.id = r.scheduled_scan_id
                WHERE r.user_id = %s AND r.scheduled_scan_id = %s
                ORDER BY r.id DESC LIMIT %s
            """, (user_id, schedule_id, limit))
        else:
            cur.execute("""
                SELECT r.id, r.scheduled_scan_id, s.name AS schedule_name,
                       r.target_url, r.started_at, r.finished_at, r.duration_seconds,
                       r.result, r.total_findings, r.critical, r.high, r.medium, r.low, r.info,
                       r.report_filename
                FROM scheduled_scan_runs r
                JOIN scheduled_scans s ON s.id = r.scheduled_scan_id
                WHERE r.user_id = %s
                ORDER BY r.id DESC LIMIT %s
            """, (user_id, limit))
        rows = cur.fetchall()
        # Convert datetime fields: old records stored UTC, new ones store local.
        # We detect by comparing to local now — if > 1h ahead it's likely UTC, shift it.
        from datetime import datetime as _dt, timedelta as _td
        import time as _t
        _offset_sec = -(_t.timezone if _t.localtime().tm_isdst == 0 else _t.altzone)
        _offset = _td(seconds=_offset_sec)
        _now_local = _dt.now()
        for row in (rows or []):
            for col in ('started_at', 'finished_at', 'created_at'):
                val = row.get(col)
                if isinstance(val, _dt):
                    # If the stored time is more than 1h behind local now AND
                    # adding local offset makes it closer to now → it was stored as UTC
                    shifted = val + _offset
                    diff_orig    = abs((_now_local - val).total_seconds())
                    diff_shifted = abs((_now_local - shifted).total_seconds())
                    use = shifted if diff_shifted < diff_orig else val
                    row[col] = use.strftime('%Y-%m-%d %H:%M:%S')
        return rows


# ── Scheduled Scan Vulnerabilities ────────────────────────────────────────────

def insert_scheduled_scan_vulns(scheduled_scan_id, run_id, user_id, target_url, vuln_list):
    """Bulk-insert tracked vulnerabilities from a completed scheduled run."""
    if not vuln_list:
        return
    from datetime import datetime
    now = datetime.utcnow()
    rows = []
    for v in vuln_list:
        rows.append((
            scheduled_scan_id, run_id, user_id, target_url[:2048],
            (v.get('Test') or v.get('name') or 'Unknown')[:255],
            (v.get('Severity') or 'info').lower()[:50],
            'fixed' if v.get('_fixed') else 'open',
            v.get('Finding') or '',
            v.get('Vulnerable Path') or '',
            v.get('Remediation') or '',
            v.get('Resolution Steps') or '',
            1 if v.get('_fixed') else 0,
            now if v.get('_fixed') else None,
            now,
        ))
    with get_connection() as conn:
        cur = conn.cursor()
        cur.executemany("""
            INSERT INTO scheduled_scan_vulns
                (scheduled_scan_id, run_id, user_id, target_url,
                 name, severity, status, finding, vulnerable_path,
                 remediation, resolution_steps, is_fixed, fixed_at, discovered_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, rows)


def get_scheduled_scan_vulns(user_id, schedule_id=None, severity=None, fixed=None):
    """Fetch tracked vulnerabilities for a user with optional filters."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        sql = """
            SELECT v.id, v.scheduled_scan_id, v.run_id, v.target_url,
                   v.name, v.severity, v.status, v.finding, v.vulnerable_path,
                   v.remediation, v.resolution_steps, v.is_fixed, v.fixed_at, v.discovered_at,
                   s.name AS schedule_name
            FROM scheduled_scan_vulns v
            JOIN scheduled_scans s ON s.id = v.scheduled_scan_id
            WHERE v.user_id = %s
        """
        params = [user_id]
        if schedule_id:
            sql += " AND v.scheduled_scan_id = %s"; params.append(schedule_id)
        if severity:
            sql += " AND LOWER(v.severity) = %s"; params.append(severity.lower())
        if fixed is True:
            sql += " AND v.is_fixed = 1"
        elif fixed is False:
            sql += " AND v.is_fixed = 0"
        sql += " ORDER BY v.id DESC"
        cur.execute(sql, params)
        rows = cur.fetchall()
    return [{
        'id':               r['id'],
        'scheduled_scan_id': r['scheduled_scan_id'],
        'schedule_name':    r['schedule_name'],
        'run_id':           r['run_id'],
        'target_url':       r['target_url'],
        'name':             r['name'],
        'severity':         r['severity'],
        'status':           r['status'],
        'finding':          r['finding'],
        'vulnerable_path':  r['vulnerable_path'],
        'remediation':      r['remediation'],
        'resolution_steps': r['resolution_steps'],
        'is_fixed':         bool(r['is_fixed']),
        'fixed_at':         r['fixed_at'],
        'discovered_at':    r['discovered_at'],
        '_display_status':  'Fixed' if r['is_fixed'] else (r['status'] or 'Open'),
    } for r in rows]


def toggle_scheduled_vuln_fixed(vuln_id, user_id):
    """Toggle is_fixed on a tracked scheduled vuln.
    Returns (new_is_fixed: bool, new_display_status: str) or None."""
    from datetime import datetime
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT is_fixed, status FROM scheduled_scan_vulns WHERE id = %s AND user_id = %s",
                    (vuln_id, user_id))
        r = cur.fetchone()
        if not r:
            return None
        new_fixed = 0 if r['is_fixed'] else 1
        fixed_at = datetime.utcnow() if new_fixed else None
        cur.execute("""
            UPDATE scheduled_scan_vulns
            SET is_fixed = %s, fixed_at = %s, status = %s
            WHERE id = %s AND user_id = %s
        """, (new_fixed, fixed_at, 'fixed' if new_fixed else 'open', vuln_id, user_id))
    return (bool(new_fixed), 'Fixed' if new_fixed else (r['status'] or 'Open'))


def get_scheduled_scan_stats(user_id):
    """Aggregate stats for the Scheduled Scans dashboard cards.
    Returns: active_schedules, runs_completed, vulns_fixed, priority_vulns, next_run_at."""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM scheduled_scans WHERE user_id = %s AND status = 'active'",
            (user_id,))
        active = (cur.fetchone() or {}).get('cnt', 0)
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM scheduled_scan_runs WHERE user_id = %s AND result != 'pending'",
            (user_id,))
        runs_done = (cur.fetchone() or {}).get('cnt', 0)
        cur.execute(
            "SELECT COUNT(*) AS cnt FROM scheduled_scan_vulns WHERE user_id = %s AND is_fixed = 1",
            (user_id,))
        fixed = (cur.fetchone() or {}).get('cnt', 0)
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM scheduled_scan_vulns
            WHERE user_id = %s AND is_fixed = 0 AND LOWER(severity) IN ('critical','high')
        """, (user_id,))
        priority = (cur.fetchone() or {}).get('cnt', 0)
        cur.execute("""
            SELECT MIN(next_run_at) AS nxt FROM scheduled_scans
            WHERE user_id = %s AND status = 'active' AND next_run_at IS NOT NULL
        """, (user_id,))
        nxt = (cur.fetchone() or {}).get('nxt')
    # Convert next_run_at from UTC to local if needed (same heuristic as _decode_schedule)
    if nxt is not None:
        from datetime import datetime as _dt, timedelta as _td
        import time as _t
        _offset_sec = -(_t.timezone if _t.localtime().tm_isdst == 0 else _t.altzone)
        _offset     = _td(seconds=_offset_sec)
        _now_local  = _dt.now()
        if isinstance(nxt, _dt):
            shifted      = nxt + _offset
            diff_raw     = abs((_now_local - nxt).total_seconds())
            diff_shifted = abs((_now_local - shifted).total_seconds())
            nxt = shifted if diff_shifted < diff_raw else nxt
        nxt = nxt.strftime('%Y-%m-%d %H:%M:%S') if hasattr(nxt, 'strftime') else str(nxt)

    return {
        'active_schedules': active or 0,
        'runs_completed':   runs_done or 0,
        'vulns_fixed':      fixed or 0,
        'priority_vulns':   priority or 0,
        'next_run_at':      nxt,
    }