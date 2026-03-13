-- VAPT Scanner Pro - MySQL Schema
-- Run via db/init_db.py

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    organization VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    job_title VARCHAR(255),
    country VARCHAR(10),
    experience_level VARCHAR(50),
    referral_source VARCHAR(50),
    bio TEXT,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signup_otps (
    email VARCHAR(255) NOT NULL PRIMARY KEY,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_reset_otps (
    email VARCHAR(255) NOT NULL PRIMARY KEY,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS targets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL DEFAULT 1,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'Web',
    status VARCHAR(50) NOT NULL DEFAULT 'Active',
    last_scan VARCHAR(100) DEFAULT 'Never',
    scan_count INT NOT NULL DEFAULT 0,
    description TEXT,
    total_vulns INT NOT NULL DEFAULT 0,
    vuln_counts_json TEXT,
    scan_config_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uk_targets_user_url (user_id, url(767))
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_id INT NOT NULL,
    scan_time VARCHAR(100) NOT NULL,
    total INT NOT NULL DEFAULT 0,
    critical INT NOT NULL DEFAULT 0,
    high INT NOT NULL DEFAULT 0,
    medium INT NOT NULL DEFAULT 0,
    low INT NOT NULL DEFAULT 0,
    info INT NOT NULL DEFAULT 0,
    report_filename VARCHAR(512),
    runtime_seconds INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_scan_history_target (target_id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL DEFAULT 1,
    target_id INT NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    scan_date VARCHAR(100) NOT NULL,
    test VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    finding TEXT,
    vulnerable_path TEXT,
    remediation TEXT,
    resolution_steps TEXT,
    is_fixed TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    INDEX idx_vuln_target (target_id),
    INDEX idx_vuln_user (user_id),
    INDEX idx_vuln_severity (severity),
    INDEX idx_vuln_fixed (is_fixed)
);

CREATE TABLE IF NOT EXISTS reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL DEFAULT 1,
    name VARCHAR(255) NOT NULL,
    target_url VARCHAR(2048) NOT NULL,
    filename VARCHAR(512) NOT NULL,
    date VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Completed',
    vuln_counts_json TEXT,
    total INT NOT NULL DEFAULT 0,
    runtime_seconds INT,
    scan_time VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reports_target (target_url(767)),
    INDEX idx_reports_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ── SCHEDULED SCANS ────────────────────────────────────────────────────────
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
);

-- ── SCHEDULED SCAN RUNS ─────────────────────────────────────────────────────
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
);

-- ── SCHEDULED SCAN VULNERABILITIES ──────────────────────────────────────────
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
);