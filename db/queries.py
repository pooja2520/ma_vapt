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
    """Store or replace OTP for signup verification. email is normalized (lower)."""
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
    """Store or replace OTP for password reset. email is normalized (lower)."""
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
