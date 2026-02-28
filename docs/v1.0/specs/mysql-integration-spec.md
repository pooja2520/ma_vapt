# MySQL Integration Specification

## Overview
Replace in-memory data storage with MySQL database persistence for the VAPT Scanner Pro application. All application data must survive server restarts and support multi-instance deployment.

## User Stories

### US1: Users
- **US1.1** As an admin, I want user accounts stored in MySQL so credentials persist across restarts.
- **US1.2** As a user, I want secure password hashing (bcrypt) preserved in the database.

### US2: Targets
- **US2.1** As a user, I want scan targets persisted so I don't lose them on restart.
- **US2.2** As a user, I want target metadata (name, url, type, description, status) stored and retrievable.
- **US2.3** As a user, I want scan history per target (last 20 entries) persisted.

### US3: Vulnerabilities
- **US3.1** As a user, I want all vulnerability findings stored in MySQL with full details.
- **US3.2** As a user, I want to filter vulnerabilities by severity, status, and search.
- **US3.3** As a user, I want to toggle fixed/unfixed status and have it persisted.

### US4: Reports
- **US4.1** As a user, I want report metadata stored in MySQL.
- **US4.2** As a user, I want to download historical reports; file path stored in DB.

### US5: Dashboard
- **US5.1** As a user, I want dashboard stats computed from DB (not in-memory).
- **US5.2** As a user, I want scan history and charts derived from persisted data.

## Acceptance Criteria

| ID | Criterion | Priority |
|----|-----------|----------|
| AC1 | All CRUD operations for targets use MySQL | Must |
| AC2 | All vulnerabilities from scans are inserted into MySQL | Must |
| AC3 | Reports metadata and file paths stored in MySQL | Must |
| AC4 | User authentication uses MySQL for lookup | Must |
| AC5 | Dashboard stats computed via SQL aggregation | Must |
| AC6 | Vulnerability fix toggle persists to DB | Must |
| AC7 | Application starts without MySQL = graceful error with clear message | Should |
| AC8 | Database migrations/schema creation script provided | Must |

## Non-Functional Requirements

- **NFR1** Database credentials via environment variables (no hardcoding).
- **NFR2** Connection pooling for efficiency.
- **NFR3** No data loss on normal operations; use transactions where appropriate.
- **NFR4** Runtime-only state (active_scan, auth_sessions, update_queue, scan_results) remains in-memory—no DB persistence needed.

## Out of Scope
- User registration (admin-only for now).
- Multi-tenancy or user-scoped data isolation.
- Report file storage in DB (BLOB)—file paths only.
