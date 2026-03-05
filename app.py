from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session, copy_current_request_context
import os
import requests
import json
import queue
import threading
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
from vapt_auto import perform_vapt_scan

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5')

# Initialize database on startup
_db_initialized = False


def init_db():
    """Create database if not exists, run schema, seed admin. Idempotent."""
    global _db_initialized
    if _db_initialized:
        return
    from db.init_db import init_database, test_connection
    init_database()
    if not test_connection():
        raise RuntimeError(
            "Cannot connect to MySQL. Please ensure MySQL is running and .env has correct "
            "MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE. Run: python -m db.init_db"
        )
    _db_initialized = True


@app.before_request
def ensure_db_initialized():
    """Ensure DB and tables exist before first request (handles flask run, gunicorn, etc.)."""
    init_db()
    # Ensure user_id in session for logged-in users (migration for old sessions)
    if 'user_email' in session and 'user_id' not in session:
        import db
        user = db.get_user_by_email(session['user_email'])
        if user:
            session['user_id'] = user['id']

@app.context_processor
def inject_current_user():
    """Make current user available in all templates."""
    if 'user_email' in session:
        return {
            'current_user': {
                'id': session.get('user_id'),
                'name': session.get('user_name', ''),
                'email': session.get('user_email', ''),
                'role': session.get('user_role', 'user'),
            }
        }
    return {'current_user': None}

# Scan engine state (runtime only, not persisted) — keyed by user_id for multi-user isolation
active_scans = {}
scan_results = {}
update_queues = {}
auth_sessions = {}  # key: (user_id, target_key)


def normalize_target_url(url):
    """Normalize target URL for auth_sessions key — http/https share same session."""
    if not url or not isinstance(url, str):
        return url or ''
    from urllib.parse import urlparse
    u = url.strip()
    if not u.startswith(('http://', 'https://')):
        u = 'https://' + u
    p = urlparse(u)
    host = (p.netloc or '').lower()
    path = (p.path or '/').rstrip('/') or '/'
    return host + path


def _get_active_scan(uid):
    if uid is None:
        return {'running': False, 'target': '', 'logs': [], 'phase': 0, 'phase_name': '', 'progress': 0, 'started_at': None}
    if uid not in active_scans:
        active_scans[uid] = {'running': False, 'target': '', 'logs': [], 'phase': 0, 'phase_name': '', 'progress': 0, 'started_at': None}
    return active_scans[uid]

def _get_scan_results(uid):
    if uid is None:
        return {}
    if uid not in scan_results:
        scan_results[uid] = {}
    return scan_results[uid]

def _get_update_queue(uid):
    if uid is None:
        return queue.Queue()
    if uid not in update_queues:
        update_queues[uid] = queue.Queue()
    return update_queues[uid]


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please sign in to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


def severity_counts(vuln_list):
    c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vuln_list:
        sev = v.get('Severity', '').lower()
        if sev in c:
            c[sev] += 1
    return c


def log(msg, uid):
    """Append log line to user's scan state and queue for SSE."""
    if uid is None:
        return
    ts = datetime.now().strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    state = _get_active_scan(uid)
    state['logs'].append(line)
    _get_update_queue(uid).put({'type': 'log', 'message': line})


def _send_email(to_email, subject, body_text, body_html=None):
    """Send email using .env MAIL_* settings. body_html optional for multipart. Returns True on success."""
    host = os.environ.get('MAIL_SERVER', '')
    port = int(os.environ.get('MAIL_PORT', '587'))
    username = os.environ.get('MAIL_USERNAME', '')
    password = os.environ.get('MAIL_PASSWORD', '')
    if not host or not username or not password:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = username
        msg['To'] = to_email
        msg.attach(MIMEText(body_text, 'plain'))
        if body_html:
            msg.attach(MIMEText(body_html, 'html'))
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(username, password)
            server.sendmail(username, [to_email], msg.as_string())
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    import db
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    if not email or not password:
        flash('Email and password are required.', 'error')
        return redirect(url_for('index'))
    user = db.get_user_by_email(email)
    if user and check_password_hash(user['password_hash'], password):
        session.clear()
        session['user_id'] = user['id']
        session['user_email'] = email
        session['user_name'] = user['name']
        session['user_role'] = user['role']
        session.permanent = True
        return redirect(url_for('dashboard'))
    flash('Invalid email or password. Please try again.', 'error')
    return redirect(url_for('index'))


@app.route('/signup', methods=['GET'])
def signup_page():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('signup.html')


@app.route('/signup/send-otp', methods=['POST'])
def signup_send_otp():
    """Generate OTP, store hashed, send email. Expects JSON { email }."""
    import db
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'ok': False, 'error': 'Valid email is required.'}), 400
    if db.get_user_by_email(email):
        return jsonify({'ok': False, 'error': 'An account with this email already exists.'}), 400
    import random
    otp_plain = ''.join(str(random.randint(0, 9)) for _ in range(6))
    otp_hash = generate_password_hash(otp_plain)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.save_signup_otp(email, otp_hash, expires_at)
    subject = 'Verify your email — VAPT Scanner Pro'
    body_text = (
        f'Your VAPT Scanner Pro verification code is: {otp_plain}\n\n'
        'This code expires in 10 minutes. Do not share it with anyone.\n\n'
        'If you did not request this code, you can safely ignore this email.'
    )
    body_html = render_template(
        'emails/verification_code.html',
        otp_code=otp_plain,
        expiry_minutes=10,
        product_name='VAPT Scanner Pro',
    )
    if not _send_email(email, subject, body_text, body_html):
        return jsonify({'ok': False, 'error': 'Failed to send verification email. Please try again later.'}), 500
    return jsonify({'ok': True})


@app.route('/signup', methods=['POST'])
def signup():
    import db
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    name = request.form.get('name', '').strip() or f'{first_name} {last_name}'.strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    confirm = request.form.get('confirm_password', '').strip()
    otp = request.form.get('otp', '').strip()
    role = request.form.get('role', '').strip() or 'user'
    organization = request.form.get('organization', '').strip() or None
    job_title = request.form.get('job_title', '').strip() or None
    country = request.form.get('country', '').strip() or None
    experience = request.form.get('experience', '').strip() or None
    referral = request.form.get('referral', '').strip() or None
    bio = request.form.get('bio', '').strip() or None

    if not all([name, email, password]):
        flash('Name, email and password are required.', 'error')
        return redirect(url_for('signup_page'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('signup_page'))
    if password != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('signup_page'))
    if len(otp) != 6:
        flash('Please enter the complete 6-digit verification code.', 'error')
        return redirect(url_for('signup_page'))
    if not db.verify_signup_otp(email, otp):
        flash('Invalid or expired verification code. Please request a new code.', 'error')
        return redirect(url_for('signup_page'))

    user = db.create_user(
        email=email,
        name=name,
        password_hash=generate_password_hash(password),
        role=role,
        first_name=first_name or None,
        last_name=last_name or None,
        organization=organization,
        job_title=job_title,
        country=country,
        experience_level=experience,
        referral_source=referral,
        bio=bio,
    )
    if user is None:
        flash('An account with this email already exists. Please sign in.', 'error')
        return redirect(url_for('index'))
    db.delete_signup_otp(email)
    flash('Account created successfully! Please sign in.', 'info')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')


@app.route('/forgot-password/send-otp', methods=['POST'])
def forgot_password_send_otp():
    """Send password reset OTP to email. Expects JSON { email }."""
    import db
    import random
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email:
        return jsonify({'ok': False, 'error': 'Valid email is required.'}), 400
    user = db.get_user_by_email(email)
    if not user:
        return jsonify({'ok': False, 'error': 'No account found with this email address.'}), 400
    otp_plain = ''.join(str(random.randint(0, 9)) for _ in range(6))
    otp_hash = generate_password_hash(otp_plain)
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.save_password_reset_otp(email, otp_hash, expires_at)
    subject = 'Reset your password — VAPT Scanner Pro'
    body_text = (
        f'Your password reset code is: {otp_plain}\n\n'
        'This code expires in 10 minutes. Do not share it with anyone.\n\n'
        'If you did not request a password reset, you can safely ignore this email.'
    )
    body_html = render_template(
        'emails/password_reset_code.html',
        otp_code=otp_plain,
        expiry_minutes=10,
        product_name='VAPT Scanner Pro',
    )
    if not _send_email(email, subject, body_text, body_html):
        return jsonify({'ok': False, 'error': 'Failed to send verification email. Please try again later.'}), 500
    return jsonify({'ok': True})


@app.route('/reset-password', methods=['GET'])
def reset_password_page():
    email = request.args.get('email', '').strip().lower()
    if not email:
        flash('Please request a password reset from the forgot password page.', 'error')
        return redirect(url_for('forgot_password'))
    return render_template('reset-password.html', email=email)


@app.route('/reset-password', methods=['POST'])
def reset_password():
    import db
    email = request.form.get('email', '').strip().lower()
    otp = request.form.get('otp', '').strip()
    password = request.form.get('password', '').strip()
    confirm = request.form.get('confirm_password', '').strip()
    if not email or '@' not in email:
        flash('Invalid email.', 'error')
        return redirect(url_for('forgot_password'))
    if len(otp) != 6:
        flash('Please enter the complete 6-digit verification code.', 'error')
        return redirect(url_for('reset_password_page', email=email))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('reset_password_page', email=email))
    if password != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('reset_password_page', email=email))
    if not db.verify_password_reset_otp(email, otp):
        flash('Invalid or expired verification code. Please request a new code.', 'error')
        return redirect(url_for('reset_password_page', email=email))
    if not db.update_user_password_by_email(email, generate_password_hash(password)):
        flash('Something went wrong. Please try again.', 'error')
        return redirect(url_for('reset_password_page', email=email))
    db.delete_password_reset_otp(email)
    flash('Password reset successfully. Please sign in with your new password.', 'info')
    return redirect(url_for('index'))


@app.route('/check-email')
def check_email():
    return render_template('check-email.html')


# ─────────────────────────────────────────────
#  MAIN APP ROUTES
# ─────────────────────────────────────────────

def _uid():
    """Current user id from session."""
    return session.get('user_id')


@app.route('/dashboard')
@login_required
def dashboard():
    import db
    stats = db.get_dashboard_stats(_uid())
    return render_template('dashboard.html', user_name=session.get('user_name'), stats=stats)


@app.route('/scanning')
@login_required
def scanning():
    return render_template('scanning.html')


@app.route('/targets')
@login_required
def targets():
    return render_template('targets.html')


@app.route('/targets/create')
@login_required
def target_create():
    return render_template('target-create.html')


@app.route('/targets/<int:target_id>/view')
@login_required
def target_view(target_id):
    return render_template('target-view.html', target_id=target_id)


@app.route('/targets/<int:target_id>/edit')
@login_required
def target_edit(target_id):
    return render_template('target-edit.html', target_id=target_id)


@app.route('/vulnerabilities')
@login_required
def vulnerabilities():
    return render_template('vulnerabilities.html')


@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vulnerability_view(vuln_id):
    return render_template('vulnerability-view.html', vuln_id=vuln_id)


@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')


@app.route('/reports/<int:report_id>')
@login_required
def report_view(report_id):
    return render_template('report-view.html', report_id=report_id)


@app.route('/scheduled')
@login_required
def scheduled():
    return render_template('scheduled-scans.html')


@app.route('/features')
@login_required
def features():
    return render_template('features.html')


@app.route('/documentation')
@login_required
def documentation():
    return render_template('documentation.html')


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


# ─────────────────────────────────────────────
#  LIVE DATA API ENDPOINTS
# ─────────────────────────────────────────────

@app.route('/api/notifications')
@login_required
def api_notifications():
    """
    Return live notifications derived from real DB data:
      - Critical / high vulnerabilities found recently
      - Completed scans
      - Newly added targets
    Each item: { id, type, title, body, time_label, dot_color, read }
    """
    import db
    uid = _uid()
    notifications = []

    # ── 1. Recent critical/high vulnerabilities ──────────────────────────
    try:
        recent_vulns = db.get_recent_vulnerabilities(uid, limit=20)
        seen_vuln_ids = set()
        for v in recent_vulns:
            sev = (v.get('severity') or v.get('Severity', '')).lower()
            if sev not in ('critical', 'high'):
                continue
            vid = v.get('id') or v.get('test', '')
            if vid in seen_vuln_ids:
                continue
            seen_vuln_ids.add(vid)
            test_name = v.get('test') or v.get('finding') or 'Unknown vulnerability'
            target = (v.get('target_url') or '').replace('https://', '').replace('http://', '').split('/')[0]
            scan_date = v.get('scan_date') or v.get('date') or ''
            # Human-readable time label
            try:
                dt = datetime.strptime(scan_date, '%Y-%m-%d %H:%M')
                diff = datetime.now() - dt
                if diff.seconds < 3600 and diff.days == 0:
                    time_label = f"{diff.seconds // 60} min ago"
                elif diff.days == 0:
                    time_label = f"{diff.seconds // 3600} hr ago"
                else:
                    time_label = f"{diff.days}d ago"
            except Exception:
                time_label = scan_date or 'Recently'
            notifications.append({
                'id':         f"vuln_{vid}",
                'type':       'vulnerability',
                'dot_color':  'r' if sev == 'critical' else 'o',
                'title':      f"{'Critical' if sev == 'critical' else 'High'} vulnerability found",
                'body':       f"{test_name}" + (f" on {target}" if target else ''),
                'time_label': time_label,
                'read':       False,
                'href':       '/vulnerabilities',
            })
            if len(notifications) >= 5:
                break
    except Exception as e:
        app.logger.warning(f"Notifications: vuln fetch failed: {e}")

    # ── 2. Recently completed scans ──────────────────────────────────────
    try:
        reports = db.get_reports(uid)
        for r in reports[:3]:
            rid    = r.get('id', '')
            target = (r.get('target_url') or r.get('name', '')).replace('https://', '').replace('http://', '').split('/')[0]
            date   = r.get('date') or r.get('scan_time') or ''
            total  = r.get('total', 0)
            try:
                dt = datetime.strptime(date, '%Y-%m-%d %H:%M')
                diff = datetime.now() - dt
                if diff.seconds < 3600 and diff.days == 0:
                    time_label = f"{diff.seconds // 60} min ago"
                elif diff.days == 0:
                    time_label = f"{diff.seconds // 3600} hr ago"
                else:
                    time_label = f"{diff.days}d ago"
            except Exception:
                time_label = date or 'Recently'
            notifications.append({
                'id':         f"scan_{rid}",
                'type':       'scan',
                'dot_color':  'b',
                'title':      'Scan completed',
                'body':       f"{target} — {total} finding{'s' if total != 1 else ''} discovered",
                'time_label': time_label,
                'read':       False,
                'href':       f"/reports/{rid}" if rid else '/reports',
            })
    except Exception as e:
        app.logger.warning(f"Notifications: scan fetch failed: {e}")

    # ── 3. Recently added targets ────────────────────────────────────────
    try:
        targets = db.get_all_targets(uid)
        for t in targets[:2]:
            tid    = t.get('id', '')
            url    = (t.get('url') or '').replace('https://', '').replace('http://', '').split('/')[0]
            created = t.get('created_at') or t.get('date') or ''
            try:
                if isinstance(created, str) and created:
                    dt = datetime.strptime(created[:16], '%Y-%m-%d %H:%M')
                    diff = datetime.now() - dt
                    if diff.seconds < 3600 and diff.days == 0:
                        time_label = f"{diff.seconds // 60} min ago"
                    elif diff.days == 0:
                        time_label = f"{diff.seconds // 3600} hr ago"
                    else:
                        time_label = f"{diff.days}d ago"
                else:
                    time_label = 'Recently'
            except Exception:
                time_label = 'Recently'
            notifications.append({
                'id':         f"target_{tid}",
                'type':       'target',
                'dot_color':  'g',
                'title':      'Target added',
                'body':       f"{url} was added to your targets",
                'time_label': time_label,
                'read':       False,
                'href':       f"/targets/{tid}/view" if tid else '/targets',
            })
    except Exception as e:
        app.logger.warning(f"Notifications: target fetch failed: {e}")

    # Cap at 8 and count unread
    notifications = notifications[:8]
    unread = sum(1 for n in notifications if not n['read'])
    return jsonify({'notifications': notifications, 'unread': unread})


@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    """Live dashboard statistics with enhanced per-scan metrics."""
    import db
    recent_rows = db.get_recent_vulnerabilities(_uid(), 5)
    recent = [{
        'test': v.get('test', ''),
        'severity': v.get('severity', ''),
        'target': v.get('target_url', ''),
        'status': v.get('status', ''),
        'finding': v.get('finding', ''),
    } for v in recent_rows]

    reports = db.get_reports(_uid())
    total_scans = len(reports)
    completed = sum(1 for r in reports if r.get('status') == 'Completed')

    # Per-scan enriched history (last 10)
    scan_history = []
    for r in reports[:10]:
        total = r.get('total', 0)
        vc    = r.get('vuln_counts', {})
        crit  = vc.get('critical', 0)
        high  = vc.get('high', 0)
        med   = vc.get('medium', 0)
        low   = vc.get('low', 0)
        info  = vc.get('info', 0)
        safe_count  = med + low + info
        success_pct = round((safe_count / total * 100), 1) if total > 0 else 100.0
        vuln_pct    = round(((crit + high) / total * 100), 1) if total > 0 else 0.0
        target_host = r.get('target_url', r.get('name', '')).replace('https://','').replace('http://','').split('/')[0]
        scan_history.append({
            'id':          r.get('id'),
            'name':        r.get('name', ''),
            'target':      target_host,
            'date':        r.get('date', ''),
            'scan_time':   r.get('scan_time', r.get('date', '')),
            'runtime':     r.get('runtime_seconds', None),
            'status':      r.get('status', 'Completed'),
            'total':       total,
            'critical':    crit,
            'high':        high,
            'medium':      med,
            'low':         low,
            'info':        info,
            'success_pct': success_pct,
            'vuln_pct':    vuln_pct,
        })

    stats = db.get_dashboard_stats(_uid())
    total_vulns = stats.get('total', 0)
    def pct(n): return round(n / total_vulns * 100, 1) if total_vulns > 0 else 0
    severity_pct = {
        'critical': pct(stats.get('critical', 0)),
        'high':     pct(stats.get('high', 0)),
        'medium':   pct(stats.get('medium', 0)),
        'low':      pct(stats.get('low', 0)),
        'info':     pct(stats.get('info', 0)),
    }

    bar_labels, bar_crit, bar_high, bar_med, bar_low, bar_info = [], [], [], [], [], []
    for entry in list(reversed(scan_history))[-8:]:
        bar_labels.append(entry['target'][:12] or entry['date'])
        bar_crit.append(entry.get('critical', 0))
        bar_high.append(entry.get('high', 0))
        bar_med.append(entry.get('medium', 0))
        bar_low.append(entry.get('low', 0))
        bar_info.append(entry.get('info', 0))

    uid = _uid()
    asc = _get_active_scan(uid) if uid else {}
    live_scan = {
        'running': asc.get('running', False),
        'target':  asc.get('target', ''),
    }

    overall_success = round(
        sum(s['success_pct'] for s in scan_history) / len(scan_history), 1
    ) if scan_history else None

    targets = db.get_all_targets(_uid())
    return jsonify({
        'stats':                  stats,
        'severity_pct':           severity_pct,
        'recent_vulnerabilities': recent,
        'total_targets':          len(targets),
        'total_reports':          total_scans,
        'completed_scans':        completed,
        'scan_history':           scan_history,
        'bar_chart':              {'labels': bar_labels, 'critical': bar_crit, 'high': bar_high, 'medium': bar_med, 'low': bar_low, 'info': bar_info},
        'live_scan':              live_scan,
        'overall_success_pct':    overall_success,
    })


@app.route('/api/targets')
@login_required
def api_targets():
    import db
    uid = _uid()
    targets = db.get_all_targets(uid)

    # Determine if a scan is currently running and which target URL it's for
    asc = _get_active_scan(uid) if uid else {}
    live_target_url = asc.get('target', '').strip().lower() if asc.get('running') else None

    enriched = []
    for t in targets:
        t = dict(t)

        # ── 1. Inject vuln_counts if missing ─────────────────────────────
        if 'vuln_counts' not in t or not t['vuln_counts']:
            try:
                vulns = db.get_vulnerabilities_by_target_url(t['url'], uid, limit=10000)
                vc = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for v in vulns:
                    sev = (v.get('severity') or v.get('Severity', '')).lower()
                    if sev in vc:
                        vc[sev] += 1
                t['vuln_counts'] = vc
            except Exception:
                t['vuln_counts'] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        # ── 2. Inject scan_count if missing ──────────────────────────────
        if 'scan_count' not in t or t['scan_count'] is None:
            try:
                reports = db.get_reports(uid)
                t['scan_count'] = sum(
                    1 for r in reports
                    if (r.get('target_url') or '').strip().lower() == t['url'].strip().lower()
                )
            except Exception:
                t['scan_count'] = 0

        # ── 3. Inject last_scan if missing ───────────────────────────────
        if 'last_scan' not in t or not t['last_scan']:
            try:
                reports = db.get_reports(uid)
                target_reports = [
                    r for r in reports
                    if (r.get('target_url') or '').strip().lower() == t['url'].strip().lower()
                ]
                t['last_scan'] = target_reports[0]['date'] if target_reports else 'Never'
            except Exception:
                t['last_scan'] = 'Never'

        # ── 4. Overlay live scan_status if this target is currently scanning
        if live_target_url and t.get('url', '').strip().lower() == live_target_url:
            t['scan_status'] = 'running'
        elif 'scan_status' not in t:
            # Derive from last_scan / existing status
            existing_status = (t.get('status') or '').lower()
            if existing_status in ('running', 'scanning'):
                t['scan_status'] = 'running'
            elif t.get('last_scan') and t['last_scan'] != 'Never':
                t['scan_status'] = 'completed'
            else:
                t['scan_status'] = 'pending'

        enriched.append(t)

    return jsonify({'targets': enriched})


@app.route('/api/targets', methods=['POST'])
@login_required
def api_target_add():
    import db
    data = request.get_json()
    url = data.get('url', '').strip()
    name = data.get('name', '').strip()
    if not url:
        return jsonify({'status': 'error', 'message': 'URL required'})
    if len(url) > 2048:
        return jsonify({'status': 'error', 'message': 'URL too long'})
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    auth_config = data.get('auth_config')
    scan_config = auth_config if isinstance(auth_config, dict) else None
    t = db.get_or_create_target(
        url,
        _uid(),
        name=name or None,
        ttype=data.get('type'),
        description=data.get('description', ''),
        scan_config=scan_config
    )
    if scan_config:
        db.update_target(t['id'], _uid(), scan_config=scan_config)
        t = db.get_target_by_id(t['id'], _uid())
    return jsonify({'status': 'success', 'target': t})


@app.route('/api/targets/<int:target_id>', methods=['GET'])
@login_required
def api_target_get(target_id):
    import db
    t = db.get_target_by_id(target_id, _uid())
    if not t:
        return jsonify({'status': 'error', 'message': 'Target not found'})
    recent = db.get_vulnerabilities_by_target_url(t['url'], _uid(), limit=10)
    result = dict(t)
    result['recent_vulns'] = recent
    return jsonify({'status': 'ok', 'target': result})


@app.route('/api/targets/<int:target_id>', methods=['PUT'])
@login_required
def api_target_update(target_id):
    import db
    t = db.get_target_by_id(target_id, _uid())
    if not t:
        return jsonify({'status': 'error', 'message': 'Target not found'})
    data = request.get_json()
    if data.get('name'):
        db.update_target(target_id, _uid(), name=data['name'])
    if data.get('url'):
        db.update_target(target_id, _uid(), url=data['url'])
    if data.get('type'):
        db.update_target(target_id, _uid(), type=data['type'])
    if 'description' in data:
        db.update_target(target_id, _uid(), description=data.get('description', ''))
    if 'auth_config' in data and isinstance(data.get('auth_config'), dict):
        db.update_target(target_id, _uid(), scan_config=data['auth_config'])
    t = db.get_target_by_id(target_id, _uid())
    return jsonify({'status': 'success', 'target': t})


@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
@login_required
def api_target_delete(target_id):
    import db
    t = db.get_target_by_id(target_id, _uid())
    if not t:
        return jsonify({'status': 'error', 'message': 'Target not found'})
    db.delete_target(target_id, _uid())
    return jsonify({'status': 'success'})


@app.route('/api/vulnerabilities')
@login_required
def api_vulnerabilities():
    """Return all live vulnerabilities with optional filters."""
    import db
    severity_filter = request.args.get('severity', '').lower() or None
    status_filter   = request.args.get('status', '').lower() or None
    search          = request.args.get('q', '').lower() or None
    target_url      = request.args.get('target_url', '') or None
    result = db.get_vulnerabilities(_uid(), severity_filter=severity_filter,
                                    status_filter=status_filter, search=search,
                                    target_url=target_url)
    return jsonify({'vulnerabilities': result, 'total': len(result)})


def _build_excel_inputs(live_vulns):
    """Convert live DB vulnerability rows into the three inputs generate_excel_report expects.

    Returns
    -------
    results : list[dict]
        Rows with the standard column keys (Test, Severity, Status, Finding,
        Vulnerable Path, Remediation, Resolution Steps).
    live_fixed_statuses : dict
        Mapping (test_name_lower, path_lower) → 'Fixed' | original_status
        so generate_excel_report can colour rows correctly.
    discovered_paths : list[str]
        Unique Vulnerable Path values for the Discovered Paths sheet.
    """
    results             = []
    live_fixed_statuses = {}
    path_set            = set()

    for v in live_vulns:
        st       = (v.get('_display_status') or v.get('Status') or '').strip()
        is_fixed = st.lower() == 'fixed' or bool(v.get('_fixed'))
        live_st  = 'Fixed' if is_fixed else st

        row = {
            'Test':             v.get('Test', ''),
            'Severity':         v.get('Severity', ''),
            'Status':           live_st,
            'Finding':          v.get('Finding', ''),
            'Vulnerable Path':  v.get('Vulnerable Path') or v.get('target_url', ''),
            'Remediation':      v.get('Remediation', ''),
            'Resolution Steps': v.get('Resolution Steps', ''),
            'target_url':       v.get('target_url', ''),
            'scan_date':        v.get('scan_date', ''),
        }
        results.append(row)

        # Build live_fixed_statuses lookup
        test_key = (v.get('Test') or '').strip().lower()
        path_key = (v.get('Vulnerable Path') or v.get('target_url') or '').strip().lower()
        live_fixed_statuses[(test_key, path_key)] = live_st

        # Collect discovered paths
        vp = v.get('Vulnerable Path') or ''
        if vp and vp not in ('N/A', '—', ''):
            path_set.add(vp)

    return results, live_fixed_statuses, list(path_set)


@app.route('/api/reports')
@login_required
def api_reports():
    import db
    reports = db.get_reports(_uid())
    return jsonify({'reports': reports})


@app.route('/api/reports/<int:report_id>')
@login_required
def api_report_detail(report_id):
    """Return full details for a single report, vulnerabilities scoped to that scan's date."""
    import db
    report = db.get_report_by_id(report_id, _uid())
    if not report:
        return jsonify({'status': 'error', 'message': 'Report not found'}), 404

    target_url = report.get('target_url', '')
    scan_date  = report.get('scan_time') or report.get('date') or ''

    # Fetch all vulns for this URL, then scope to this specific scan's exact
    # minute so fixes in one report never bleed across other reports for the
    # same target (even when multiple scans ran on the same day).
    all_vulns = db.get_vulnerabilities(_uid(), target_url=target_url)
    if scan_date:
        scan_minute = scan_date[:16]  # "2026-03-05 15:14"
        target_vulns = [v for v in all_vulns if (v.get('scan_date') or '')[:16] == scan_minute]
        if not target_vulns:
            # Fallback: date-only for older data lacking exact times
            scan_day = scan_date[:10]
            target_vulns = [v for v in all_vulns if (v.get('scan_date') or '')[:10] == scan_day]
        if not target_vulns:        # final fallback if scan_date missing on vulns
            target_vulns = all_vulns
    else:
        target_vulns = all_vulns

    fixed_count = sum(1 for v in target_vulns if (v.get('_display_status') or v.get('Status') or '').lower() == 'fixed')
    vuln_count  = sum(1 for v in target_vulns if (v.get('_display_status') or v.get('Status') or '').lower() == 'vulnerable')
    fix_pct     = round(fixed_count / len(target_vulns) * 100) if target_vulns else 0

    result = dict(report)
    result['vulnerabilities'] = target_vulns
    result['urls_tested']     = len(target_vulns)
    result['fixed_count']     = fixed_count
    result['vuln_count']      = vuln_count
    result['fix_pct']         = fix_pct
    result['duration']        = f"{report.get('runtime_seconds', 0) // 60} min {report.get('runtime_seconds', 0) % 60} sec" if report.get('runtime_seconds') else 'N/A'

    return jsonify({'status': 'success', 'report': result})


@app.route('/api/scan-logs')
@login_required
def api_scan_logs():
    """Return all accumulated logs for the current or last scan (user-specific)."""
    uid = _uid()
    asc = _get_active_scan(uid) if uid else {}
    return jsonify({
        'running':    asc.get('running', False),
        'target':     asc.get('target', ''),
        'logs':       asc.get('logs', []),
        'phase':      asc.get('phase', 0),
        'phase_name': asc.get('phase_name', ''),
        'progress':   asc.get('progress', 0),
        'started_at': asc.get('started_at', None),
    })


@app.route('/api/reset-scan', methods=['POST'])
@login_required
def api_reset_scan():
    """Clear scan results and logs so the scanning page starts fresh (user-specific)."""
    uid = _uid()
    asc = _get_active_scan(uid) if uid else {}
    if not asc.get('running'):
        res = _get_scan_results(uid) if uid else {}
        res.clear()
        asc['logs'] = []
        asc['target'] = ''
        asc['phase'] = 0
        asc['phase_name'] = ''
        asc['progress'] = 0
        asc['started_at'] = None
    return jsonify({'status': 'ok', 'running': asc.get('running', False)})


# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  AUTH HELPERS (form login robustness)
# ─────────────────────────────────────────────

def _normalize_auth_data(data):
    """Normalize auth_data keys: support both login_url and formLoginUrl (from target storage)."""
    if not data:
        return data
    d = dict(data)
    d['login_url'] = d.get('login_url') or d.get('formLoginUrl') or ''
    d['username'] = d.get('username') or d.get('formUsername') or ''
    d['password'] = d.get('password') or d.get('formPassword') or ''
    d['username_field'] = (d.get('username_field') or d.get('formUsernameField') or 'username').strip() or 'username'
    d['password_field'] = (d.get('password_field') or d.get('formPasswordField') or 'password').strip() or 'password'
    d['success_indicator'] = (d.get('success_indicator') or d.get('formSuccessIndicator') or '').strip()
    return d


def _detect_login_form_fields(login_url):
    """
    Fetch login page and auto-detect username/password field names.
    Returns (username_field, password_field, api_login_url or None).
    For SPAs (JS-rendered, no form in HTML), suggests email/password and API URL.
    """
    try:
        r = requests.get(login_url, timeout=15, verify=False, allow_redirects=True)
        if r.status_code != 200 or 'text/html' not in r.headers.get('Content-Type', ''):
            return None, None, None
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
        soup = BeautifulSoup(r.text, 'html.parser')
        login_forms = []
        for form in soup.find_all('form'):
            inputs = form.find_all(['input', 'textarea'])
            username_field = None
            password_field = None
            for inp in inputs:
                # Use name first, fallback to id (many forms use id-only for JS binding)
                field_id = inp.get('id')
                name = inp.get('name') or field_id
                if not name:
                    continue
                itype = (inp.get('type') or 'text').lower()
                if itype == 'password':
                    password_field = name
                elif itype in ('text', 'email') and not username_field:
                    username_field = name
            if password_field:
                action = (form.get('action') or '').lower()
                form_id = (form.get('id') or '').lower()
                form_class = ' '.join(form.get('class', [])).lower()
                combined = f"{action} {form_id} {form_class}"
                is_login_like = any(kw in combined for kw in ('login', 'auth', 'signin', 'sign-in'))
                login_forms.append((1 if is_login_like else 0, username_field or 'username', password_field))
        if login_forms:
            login_forms.sort(key=lambda x: -x[0])
            user_f, pass_f = login_forms[0][1], login_forms[0][2]
            # Check for JS-driven API login: form has no action
            api_url = None
            has_form_without_action = any(
                not (f.get('action') or '').strip()
                for f in soup.find_all('form') if f.find('input', {'type': 'password'})
            )
            if has_form_without_action:
                # Prefer Playwright: capture exact URL from network (same as SPA)
                try:
                    from auth_detector import _capture_login_api_via_browser
                    br_user, br_pass, api_url = _capture_login_api_via_browser(login_url)
                    if api_url:
                        user_f, pass_f = br_user or user_f, br_pass or pass_f
                except Exception:
                    pass
                # Fallback: regex on HTML if browser fails
                if not api_url:
                    import re
                    api_path_match = re.search(r'["\']([^"\']*(?:api[^"\']*)?auth[^"\']*login[^"\']*)["\']', r.text, re.I)
                    if api_path_match:
                        path = api_path_match.group(1).strip()
                        if path.startswith('/'):
                            parsed = urlparse(login_url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            api_url = urljoin(base, path)
            return user_f, pass_f, api_url
        # No form found - likely SPA (JS-rendered). Use browser to capture exact API URL.
        spa_markers = ('id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"', 'data-reactroot')
        has_spa_marker = any(m in r.text for m in spa_markers)
        if has_spa_marker and not soup.find_all('form'):
            try:
                from auth_detector import _capture_login_api_via_browser
                user_f, pass_f, api_url = _capture_login_api_via_browser(login_url)
                if api_url:
                    return user_f or 'email', pass_f or 'password', api_url
            except Exception:
                pass
            # Fallback: probe common API paths if browser detection fails
            parsed = urlparse(login_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            candidates = ['/api/auth/login', '/auth/login', '/api/login', '/api/v1/auth/login']
            api_url = None
            for path in candidates:
                url = urljoin(base, path)
                try:
                    probe = requests.post(
                        url, json={'email': 'x', 'password': 'x'},
                        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                        timeout=5, verify=False, allow_redirects=False
                    )
                    if probe.status_code in (200, 201, 400, 401, 422):
                        api_url = url
                        break
                except Exception:
                    continue
            if not api_url:
                api_url = urljoin(base, '/api/auth/login')
            return 'email', 'password', api_url
        return None, None, None
    except Exception:
        return None, None, None


def _resolve_form_action(form_action, login_url):
    """Resolve form action (relative/empty) against login page URL."""
    if not form_action or not form_action.strip():
        return login_url
    from urllib.parse import urljoin
    return urljoin(login_url, form_action.strip())


@app.route('/api/detect-login-fields', methods=['POST'])
@login_required
def api_detect_login_fields():
    """Auto-detect username/password field names from login page HTML."""
    try:
        data = request.get_json() or {}
        login_url = (data.get('login_url') or data.get('formLoginUrl') or '').strip()
        if not login_url:
            return jsonify({'status': 'error', 'message': 'Login URL required'})
        if not login_url.startswith(('http://', 'https://')):
            login_url = 'https://' + login_url
        login_url = login_url.rstrip('/') or login_url  # normalize trailing slash
        user_field, pass_field, api_url = _detect_login_form_fields(login_url)
        if user_field and pass_field:
            resp = {
                'status': 'ok',
                'username_field': user_field,
                'password_field': pass_field,
            }
            if api_url:
                resp['api_login_url'] = api_url
                resp['message'] = 'SPA detected. Use Login URL below for API-based login.'
            return jsonify(resp)
        return jsonify({'status': 'error', 'message': 'Could not detect login form fields'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


#  VAPT SCAN API ROUTES
# ─────────────────────────────────────────────

@app.route('/test-auth', methods=['POST'])
@login_required
def test_auth():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        auth_type = data.get('auth_type', 'none')
        auth_data = data.get('auth_data', {})

        if not target:
            return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

        print(f"\n[*] Testing authentication for: {target}")
        print(f"[*] Auth type: {auth_type}")

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        req_session = requests.Session()

        if auth_type == 'form':
            auth_data = _normalize_auth_data(auth_data)
            login_url = auth_data.get('login_url', '').strip()
            username = auth_data.get('username', '').strip()
            password = auth_data.get('password', '').strip()
            username_field = (auth_data.get('username_field') or '').strip() or 'username'
            password_field = (auth_data.get('password_field') or '').strip() or 'password'
            success_indicator = (auth_data.get('success_indicator') or '').strip()

            if not all([login_url, username, password]):
                return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

            # Auto-detect field names when user left them default/empty
            if username_field == 'username' or password_field == 'password':
                detected_user, detected_pass, detected_api = _detect_login_form_fields(login_url)
                if detected_user:
                    username_field = detected_user
                if detected_pass:
                    password_field = detected_pass
                if detected_api:
                    login_url = detected_api  # Use API URL for SPA

            try:
                req_session.verify = False
                login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
                hidden_fields = {}
                post_url = login_url
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(login_page.text, 'html.parser')
                    for form in soup.find_all('form'):
                        # Resolve form action (relative/empty)
                        form_action = form.get('action', '')
                        post_url = _resolve_form_action(form_action, login_url)
                        for hidden in form.find_all('input', {'type': 'hidden'}):
                            n = hidden.get('name')
                            v = hidden.get('value')
                            if n and n not in [username_field, password_field]:
                                hidden_fields[n] = v or ''
                        break  # use first form
                except Exception:
                    pass

                login_data = {username_field: username, password_field: password}
                login_data.update(hidden_fields)
                # API-based login (SPA): POST JSON to /auth/login, /api/login, etc.
                is_api_login = '/auth/login' in post_url or '/api/login' in post_url or '/api/auth' in post_url
                if is_api_login:
                    from urllib.parse import urlparse
                    parsed = urlparse(post_url)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    api_headers = {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'Origin': origin,
                        'Referer': login_url or origin + '/',
                    }
                    login_response = req_session.post(
                        post_url, json=login_data,
                        headers=api_headers,
                        allow_redirects=True, timeout=15
                    )
                    # Try alternate API paths if 401
                    if login_response.status_code == 401:
                        for alt_path in ('/api/auth/login', '/api/login', '/api/v1/auth/login'):
                            alt_url = f"{parsed.scheme}://{parsed.netloc}{alt_path}"
                            if alt_url != post_url:
                                r2 = req_session.post(alt_url, json=login_data, headers=api_headers, allow_redirects=True, timeout=15)
                                if r2.status_code in (200, 201):
                                    login_response = r2
                                    post_url = alt_url
                                    break
                else:
                    login_response = req_session.post(post_url, data=login_data, allow_redirects=True, timeout=15)

                failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
                                    'bad credentials', 'unauthorized', 'authentication failed', 'login failed',
                                    'incorrect password', 'invalid password', 'access denied']
                has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
                # API login: 200/201 with token in body = success
                api_success = is_api_login and login_response.status_code in (200, 201) and not has_failure
                url_changed = login_response.url != login_url
                final_url_lower = login_response.url.lower()

                test_sess = requests.Session()
                test_sess.verify = False
                wrong_data = login_data.copy()
                wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
                if is_api_login:
                    wrong_response = test_sess.post(post_url, json=wrong_data, headers={'Content-Type': 'application/json'}, allow_redirects=True, timeout=15)
                else:
                    wrong_response = test_sess.post(post_url, data=wrong_data, allow_redirects=True, timeout=15)
                response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

                # Cookie-based success: new session cookies after login
                got_new_cookies = len(req_session.cookies) > 0
                # URL-based: no longer on login page (dashboard, home, etc.)
                left_login_page = 'login' not in final_url_lower or url_changed

                login_success = False
                success_reason = ""
                if api_success:
                    login_success = True
                    success_reason = 'API login successful (200/201, no error)'
                elif success_indicator and success_indicator.lower() in login_response.text.lower():
                    login_success = True
                    success_reason = f'Found success indicator "{success_indicator}"'
                elif url_changed and response_differs:
                    login_success = True
                    success_reason = 'Authentication verified (URL changed & responses differ)'
                elif url_changed and not has_failure:
                    login_success = True
                    success_reason = 'Page changed after login (no errors detected)'
                elif response_differs and not has_failure:
                    login_success = True
                    success_reason = 'Responses differ (authentication working)'
                elif got_new_cookies and not has_failure:
                    login_success = True
                    success_reason = 'Session cookies received (no error text)'
                elif left_login_page and not has_failure:
                    login_success = True
                    success_reason = 'Redirected away from login (no error text)'

                if login_success:
                    auth_key = normalize_target_url(target)
                    uid = _uid()
                    auth_sessions[(uid, auth_key)] = {
                        'type': 'form', 'session': req_session,
                        'cookies': req_session.cookies.get_dict(),
                        'login_url': login_url, 'login_data': login_data,
                        'auth_data': {'login_url': login_url, 'username': username, 'password': password,
                                      'username_field': username_field, 'password_field': password_field,
                                      'success_indicator': success_indicator},
                    }
                    return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
                else:
                    err_msg = 'Login Failed! Please check your credentials.'
                    if is_api_login and login_response.status_code == 401:
                        err_msg = f'Login Failed (401). The API at {post_url} rejected the credentials. Verify username/password and that the API endpoint is correct.'
                    return jsonify({'status': 'error', 'message': err_msg})

            except requests.exceptions.Timeout:
                return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

        elif auth_type == 'basic':
            username = auth_data.get('username', '').strip()
            password = auth_data.get('password', '').strip()
            if not all([username, password]):
                return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
            try:
                resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
                resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
                resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
                if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
                    auth_sessions[(_uid(), normalize_target_url(target))] = {'type': 'basic', 'username': username, 'password': password}
                    return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
                elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
                    auth_sessions[(_uid(), normalize_target_url(target))] = {'type': 'basic', 'username': username, 'password': password}
                    return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
                else:
                    return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
            except requests.exceptions.Timeout:
                return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


@app.route('/scan-progress')
@login_required
def scan_progress():
    """SSE endpoint — streams log lines and phase events in real time (user-specific)."""
    uid = _uid()
    asc = _get_active_scan(uid) if uid else {}
    uq = _get_update_queue(uid) if uid else queue.Queue()

    def generate():
        while asc.get('running'):
            try:
                update = uq.get(timeout=1)
                yield f"data: {json.dumps(update)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(generate(), mimetype='text/event-stream')


@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        auth_type = data.get('auth_type', 'none')
        auth_data_payload = data.get('auth_data', {})
        owasp_enabled = data.get('owasp_enabled', True)

        if not target:
            return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        print(f"\n[*] Starting scan for: {target}")

        auth_credentials = None
        uid = _uid()
        if uid is None:
            import db
            admin = db.get_user_by_email('admin@vapt.pro')
            uid = admin['id'] if admin else 1
        if auth_type != 'none' and auth_data_payload:
            auth_key = normalize_target_url(target)
            stored = auth_sessions.get((uid, auth_key))
            auth_credentials = {
                'type': auth_type,
                'data': auth_data_payload,
                'session': stored,
                'auth_data': stored.get('auth_data') if isinstance(stored, dict) else None,
            }

        # Reset state for new scan (user-specific)
        asc = _get_active_scan(uid)
        res = _get_scan_results(uid)
        uq = _get_update_queue(uid)
        asc['running'] = True
        asc['target'] = target
        asc['logs'] = []
        asc['phase'] = 1
        asc['phase_name'] = 'Network Security Testing'
        asc['progress'] = 5
        asc['started_at'] = datetime.now().isoformat()
        res.clear()

        # Mark target as "scanning" in DB so targets page shows live status
        try:
            import db as _db_mod
            _tgt = _db_mod.get_or_create_target(target, uid)
            if _tgt:
                _db_mod.update_target(_tgt['id'], uid, status='scanning')
        except Exception:
            pass

        while not uq.empty():
            try:
                uq.get_nowait()
            except queue.Empty:
                break

        def update_phase(phase_num, phase_name, progress_pct):
            asc['phase']      = phase_num
            asc['phase_name'] = phase_name
            asc['progress']   = progress_pct

        user_id = uid

        @copy_current_request_context
        def run_scan():
            import time as _time
            _scan_start = _time.time()
            try:
                log(f"🚀 Scan started for {target}", user_id)
                log(f"🔐 Authentication: {auth_type}", user_id)

                def progress_cb(msg):
                    """Forward vapt_auto events to SSE queue AND log panel."""
                    uq.put(msg)
                    if isinstance(msg, dict):
                        mtype = msg.get('type', '')
                        if mtype == 'phase':
                            phase_num = msg.get('phase', 1)
                            name      = msg.get('name', '')
                            progress_map = {1: 10, 2: 35, 3: 65, 4: 90}
                            update_phase(phase_num, name, progress_map.get(phase_num, 10))
                            log(f"📋 Phase {phase_num}: {name}", user_id)
                        elif mtype == 'crawling':
                            count = msg.get('count', 0)
                            total = msg.get('total', 50)
                            crawl_pct = 35 + int((count / max(total, 1)) * 15)
                            asc['progress'] = crawl_pct
                            log(f"🕷️ Crawling [{count}/{total}]: {msg.get('url')}", user_id)
                        elif mtype == 'crawl_complete':
                            update_phase(2, 'Crawl Complete', 50)
                            log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages", user_id)
                        elif mtype == 'crawl_start':
                            log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...", user_id)

                result = perform_vapt_scan(
                    target,
                    auth_credentials=auth_credentials,
                    owasp_enabled=owasp_enabled,
                    progress_callback=progress_cb
                )

                if result['status'] == 'success':
                    raw_results = result['results']
                    filename = result['filename']

                    # Tag each finding
                    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                    for r in raw_results:
                        r['target_url'] = target
                        r['scan_date'] = scan_time

                    sc = severity_counts(raw_results)
                    _runtime = int(_time.time() - _scan_start)

                    # Persist to DB in single transaction (user_id captured before thread)
                    import db
                    db.scan_completion_transaction(
                        target, raw_results, filename, scan_time, sc, _runtime, user_id
                    )

                    # Mark target status as completed
                    try:
                        _tgt2 = db.get_or_create_target(target, user_id)
                        if _tgt2:
                            db.update_target(_tgt2['id'], user_id, status='completed')
                    except Exception:
                        pass

                    res['last_file'] = filename
                    res['last_result'] = result

                    log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}", user_id)
                    log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}", user_id)
                    log(f"⏱️ Runtime: {_runtime}s", user_id)
                else:
                    res['last_error'] = result.get('message', 'Unknown error')
                    log(f"❌ Scan failed: {result.get('message')}", user_id)

            except Exception as e:
                print(f"[!] Scan error: {str(e)}")
                res['last_error'] = str(e)
                log(f"❌ Error: {str(e)}", user_id)
            finally:
                asc['progress'] = 100
                asc['phase']    = 4
                asc['running'] = False

        t = threading.Thread(target=run_scan)  # run_scan has @copy_current_request_context
        t.daemon = True
        t.start()

        return jsonify({'status': 'started', 'message': 'Scan started.'})

    except Exception as e:
        uid = _uid()
        if uid:
            _get_active_scan(uid)['running'] = False
        return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


@app.route('/scan-status')
@login_required
def scan_status():
    uid = _uid()
    asc = _get_active_scan(uid) if uid else {}
    res = _get_scan_results(uid) if uid else {}
    if asc.get('running'):
        return jsonify({'status': 'running'})
    elif 'last_result' in res:
        result = res['last_result']
        return jsonify({
            'status': 'success',
            'filename': result['filename'],
            'results': result['results'],
        })
    elif 'last_error' in res:
        return jsonify({'status': 'error', 'message': res['last_error']})
    else:
        return jsonify({'status': 'idle'})


@app.route('/download')
@login_required
def download():
    """Regenerate and download the latest report with live fixed status from DB."""
    import db
    from vapt_auto import generate_excel_report
    try:
        # Get the most recent report to know the target URL
        reports = db.get_reports(_uid())
        if not reports:
            return jsonify({'status': 'error', 'message': 'No reports found'})

        latest  = reports[0]
        target_url = latest.get('target_url', '')

        live_vulns = db.get_vulnerabilities(_uid(), target_url=target_url)
        if not live_vulns:
            # Fall back to the stored file
            res = _get_scan_results(_uid()) if _uid() else {}
            fname = res.get('last_file')
            if fname and os.path.exists(fname):
                return send_file(fname, as_attachment=True, download_name=os.path.basename(fname))
            return jsonify({'status': 'error', 'message': 'No data available'})

        results, live_fixed_statuses, discovered_paths = _build_excel_inputs(live_vulns)
        new_file = generate_excel_report(target_url, results, discovered_paths,
                                         live_fixed_statuses=live_fixed_statuses)
        return send_file(new_file, as_attachment=True, download_name=os.path.basename(new_file))
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


@app.route('/api/vulnerabilities/<int:vuln_id>')
@login_required
def api_vulnerability_detail(vuln_id):
    """Return a single vulnerability by id."""
    import db
    entry = db.get_vulnerability_by_id(vuln_id, _uid())
    if not entry:
        return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
    return jsonify({'status': 'success', 'vulnerability': entry})


@app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
@login_required
def api_vulnerability_fix(vuln_id):
    """Toggle fixed/unfixed on a vulnerability."""
    import db
    result = db.toggle_vulnerability_fixed(vuln_id, _uid())
    if result is None:
        return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
    new_fixed, new_status = result
    return jsonify({'status': 'success', 'new_status': new_status, 'fixed': new_fixed})


@app.route('/download-report/<int:report_id>')
@login_required
def download_report(report_id):
    """Regenerate Excel with live fixed/vulnerable status from DB, then download."""
    import db
    from vapt_auto import generate_excel_report

    report = db.get_report_by_id(report_id, _uid())
    if not report:
        return jsonify({'status': 'error', 'message': 'Report not found'}), 404

    target_url = report.get('target_url', '')
    live_vulns = db.get_vulnerabilities(_uid(), target_url=target_url)

    if not live_vulns:
        # Fall back to the original stored file
        orig = report.get('filename', '')
        if orig and os.path.exists(orig):
            return send_file(orig, as_attachment=True, download_name=os.path.basename(orig))
        return jsonify({'status': 'error', 'message': 'No vulnerability data available'}), 404

    try:
        results, live_fixed_statuses, discovered_paths = _build_excel_inputs(live_vulns)
        new_file = generate_excel_report(target_url, results, discovered_paths,
                                         live_fixed_statuses=live_fixed_statuses)
        return send_file(new_file, as_attachment=True, download_name=os.path.basename(new_file))
    except Exception as e:
        orig = report.get('filename', '')
        if orig and os.path.exists(orig):
            return send_file(orig, as_attachment=True, download_name=os.path.basename(orig))
        return jsonify({'status': 'error', 'message': f'Report generation failed: {str(e)}'}), 500


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 80)
    print("              ADVANCED VAPT SCANNER PRO")
    print("          Vulnerability Assessment & Penetration Testing Tool")
    print("=" * 80)
    try:
        init_db()
    except RuntimeError as e:
        print(f"\n[!] Startup failed: {e}")
        print("[!] Ensure MySQL is running and .env is configured. Copy .env.example to .env")
        exit(1)
    print("\n[+] Server starting...")
    print("[+] Access the scanner at: http://localhost:5005")
    print("[+] Sign up for a new account or login with: admin@vapt.pro / Admin@1234")
    print("[+] Press Ctrl+C to stop\n")
    print("=" * 80)
    print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
    print("=" * 80 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5005)