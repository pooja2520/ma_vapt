"""Initialize database: create DB if not exists, run schema, seed admin user if empty."""
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from db.config import get_db_config
from werkzeug.security import generate_password_hash


def init_database():
    """Create database if not exists, run schema, seed admin if users table is empty."""
    cfg = get_db_config()
    db_name = cfg.pop('database')
    cfg.pop('pool_name', None)
    cfg.pop('pool_size', None)
    cfg.pop('pool_reset_session', None)
    cfg.pop('autocommit', None)

    import mysql.connector
    conn = mysql.connector.connect(**cfg)
    conn.autocommit = True
    cur = conn.cursor()

    # 1. Create database if not exists
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.execute(f"USE `{db_name}`")

    # 2. Run schema - create tables if not exist
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        schema_sql = f.read()

    # Remove comment lines
    schema_clean = '\n'.join(
        line for line in schema_sql.split('\n')
        if line.strip() and not line.strip().startswith('--')
    )

    # Execute as multi-statement (more reliable than split)
    try:
        for result in cur.execute(schema_clean, multi=True):
            if result.with_rows:
                result.fetchall()
    except Exception as e:
        # Fallback: execute each statement individually
        for stmt in schema_clean.split(';'):
            stmt = stmt.strip()
            if stmt:
                try:
                    cur.execute(stmt)
                except Exception as ex:
                    err = str(ex).lower()
                    if 'already exists' not in err and 'duplicate' not in err:
                        raise RuntimeError(f"Schema failed: {ex}") from ex

    # 3. Seed admin user only if no users exist
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (email, name, password_hash, role) VALUES (%s, %s, %s, %s)",
            ('admin@vapt.pro', 'Admin User', generate_password_hash('Admin@1234'), 'admin')
        )
        print("[+] Seeded admin user: admin@vapt.pro / Admin@1234")

    # 4. Migration: add user_id to existing tables (for DBs created before multi-tenancy)
    def column_exists(table, col):
        cur.execute("""
            SELECT 1 FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """, (db_name, table, col))
        return cur.fetchone() is not None

    def run_safe(sql, msg=""):
        try:
            cur.execute(sql)
            return True
        except Exception as e:
            if 'duplicate' not in str(e).lower() and 'exists' not in str(e).lower():
                print(f"[!] Migration warning: {msg or sql} - {e}")
            return False

    if not column_exists('targets', 'scan_config_json'):
        cur.execute("ALTER TABLE targets ADD COLUMN scan_config_json TEXT AFTER vuln_counts_json")
        print("[+] Migration: added scan_config_json to targets")

    if not column_exists('targets', 'user_id'):
        cur.execute("ALTER TABLE targets ADD COLUMN user_id INT NOT NULL DEFAULT 1 AFTER id")
        cur.execute("SELECT id FROM users WHERE email = 'admin@vapt.pro' LIMIT 1")
        admin_row = cur.fetchone()
        if admin_row:
            cur.execute("UPDATE targets SET user_id = %s", (admin_row[0],))
        run_safe("ALTER TABLE targets ADD CONSTRAINT fk_targets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
        run_safe("ALTER TABLE targets DROP INDEX url", "drop url index")
        run_safe("ALTER TABLE targets ADD UNIQUE KEY uk_targets_user_url (user_id, url(767))")
        print("[+] Migration: added user_id to targets")
    if not column_exists('vulnerabilities', 'user_id'):
        cur.execute("ALTER TABLE vulnerabilities ADD COLUMN user_id INT NOT NULL DEFAULT 1 AFTER id")
        cur.execute("SELECT id FROM users WHERE email = 'admin@vapt.pro' LIMIT 1")
        admin_row = cur.fetchone()
        if admin_row:
            cur.execute("UPDATE vulnerabilities SET user_id = %s", (admin_row[0],))
        run_safe("ALTER TABLE vulnerabilities ADD CONSTRAINT fk_vuln_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
        run_safe("ALTER TABLE vulnerabilities ADD INDEX idx_vuln_user (user_id)")
        print("[+] Migration: added user_id to vulnerabilities")
    if not column_exists('reports', 'user_id'):
        cur.execute("ALTER TABLE reports ADD COLUMN user_id INT NOT NULL DEFAULT 1 AFTER id")
        cur.execute("SELECT id FROM users WHERE email = 'admin@vapt.pro' LIMIT 1")
        admin_row = cur.fetchone()
        if admin_row:
            cur.execute("UPDATE reports SET user_id = %s", (admin_row[0],))
        run_safe("ALTER TABLE reports ADD CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE")
        run_safe("ALTER TABLE reports ADD INDEX idx_reports_user (user_id)")
        print("[+] Migration: added user_id to reports")

    # Signup profile columns and OTP table
    for col, defn in [
        ('first_name', 'VARCHAR(255) NULL'),
        ('last_name', 'VARCHAR(255) NULL'),
        ('organization', 'VARCHAR(255) NULL'),
        ('job_title', 'VARCHAR(255) NULL'),
        ('country', 'VARCHAR(10) NULL'),
        ('experience_level', 'VARCHAR(50) NULL'),
        ('referral_source', 'VARCHAR(50) NULL'),
        ('bio', 'TEXT NULL'),
    ]:
        if not column_exists('users', col):
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
            print(f"[+] Migration: added users.{col}")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS signup_otps (
            email VARCHAR(255) NOT NULL PRIMARY KEY,
            otp_hash VARCHAR(255) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("[+] signup_otps table ready")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            email VARCHAR(255) NOT NULL PRIMARY KEY,
            otp_hash VARCHAR(255) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("[+] password_reset_otps table ready")

    # ── Scheduled scans tables ────────────────────────────────────────────────
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            user_id          INT NOT NULL,
            target_id        INT DEFAULT NULL,
            name             VARCHAR(255) NOT NULL,
            target_url       VARCHAR(2048) NOT NULL,
            frequency        VARCHAR(20)  NOT NULL DEFAULT 'daily',
            scan_time        VARCHAR(10)  NOT NULL DEFAULT '02:00',
            day_of_week      TINYINT      DEFAULT NULL,
            day_of_month     TINYINT      DEFAULT NULL,
            auth_type        VARCHAR(20)  NOT NULL DEFAULT 'none',
            auth_config_json TEXT         DEFAULT NULL,
            timeout_minutes  SMALLINT     NOT NULL DEFAULT 30,
            notify_on_done   TINYINT(1)   NOT NULL DEFAULT 1,
            status           VARCHAR(20)  NOT NULL DEFAULT 'active',
            run_count        INT          NOT NULL DEFAULT 0,
            last_run_at      DATETIME     DEFAULT NULL,
            next_run_at      DATETIME     DEFAULT NULL,
            created_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            updated_at       TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)   REFERENCES users(id)    ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES targets(id)  ON DELETE SET NULL,
            INDEX idx_ss_user        (user_id),
            INDEX idx_ss_status      (status),
            INDEX idx_ss_next_run    (next_run_at),
            INDEX idx_ss_user_status (user_id, status)
        )
    """)
    print("[+] scheduled_scans table ready")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scan_runs (
            id                 INT AUTO_INCREMENT PRIMARY KEY,
            scheduled_scan_id  INT NOT NULL,
            user_id            INT NOT NULL,
            target_url         VARCHAR(2048) NOT NULL,
            started_at         DATETIME  NOT NULL,
            finished_at        DATETIME  DEFAULT NULL,
            duration_seconds   INT       DEFAULT NULL,
            result             VARCHAR(20) NOT NULL DEFAULT 'pending',
            total_findings     INT NOT NULL DEFAULT 0,
            critical           INT NOT NULL DEFAULT 0,
            high               INT NOT NULL DEFAULT 0,
            medium             INT NOT NULL DEFAULT 0,
            low                INT NOT NULL DEFAULT 0,
            info               INT NOT NULL DEFAULT 0,
            report_filename    VARCHAR(512) DEFAULT NULL,
            error_message      TEXT        DEFAULT NULL,
            created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scheduled_scan_id) REFERENCES scheduled_scans(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id)           REFERENCES users(id)            ON DELETE CASCADE,
            INDEX idx_ssr_schedule (scheduled_scan_id),
            INDEX idx_ssr_user     (user_id),
            INDEX idx_ssr_result   (result),
            INDEX idx_ssr_started  (started_at)
        )
    """)
    print("[+] scheduled_scan_runs table ready")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_scan_vulns (
            id                 INT AUTO_INCREMENT PRIMARY KEY,
            scheduled_scan_id  INT NOT NULL,
            run_id             INT NOT NULL,
            user_id            INT NOT NULL,
            target_url         VARCHAR(2048) NOT NULL,
            name               VARCHAR(255) NOT NULL,
            severity           VARCHAR(50)  NOT NULL,
            status             VARCHAR(50)  NOT NULL DEFAULT 'open',
            finding            TEXT         DEFAULT NULL,
            vulnerable_path    TEXT         DEFAULT NULL,
            remediation        TEXT         DEFAULT NULL,
            resolution_steps   TEXT         DEFAULT NULL,
            is_fixed           TINYINT(1)   NOT NULL DEFAULT 0,
            fixed_at           DATETIME     DEFAULT NULL,
            discovered_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at         TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scheduled_scan_id) REFERENCES scheduled_scans(id)    ON DELETE CASCADE,
            FOREIGN KEY (run_id)            REFERENCES scheduled_scan_runs(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id)           REFERENCES users(id)               ON DELETE CASCADE,
            INDEX idx_ssv_schedule (scheduled_scan_id),
            INDEX idx_ssv_run      (run_id),
            INDEX idx_ssv_user     (user_id),
            INDEX idx_ssv_severity (severity),
            INDEX idx_ssv_fixed    (is_fixed)
        )
    """)
    print("[+] scheduled_scan_vulns table ready")

    cur.close()
    conn.close()
    print(f"[+] Database '{db_name}' initialized successfully.")


def test_connection():
    """Test that we can connect to the database."""
    from db.queries import get_pool
    try:
        pool = get_pool()
        conn = pool.get_connection()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] Database connection failed: {e}")
        return False


if __name__ == '__main__':
    init_database()