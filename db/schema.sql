-- VAPT Scanner Pro - MySQL Schema
-- Run via db/init_db.py

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
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
    UNIQUE KEY uk_targets_user_url (user_id, url)
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
    INDEX idx_reports_target (target_url),
    INDEX idx_reports_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
