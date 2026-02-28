# MySQL Integration Implementation Plan

**Goal:** Replace in-memory storage (dicts/lists) with MySQL persistence so that users, targets, vulnerabilities, and reports survive server restarts and support scalable deployment.

---

## User Review Required

> [!IMPORTANT]
> - **Breaking change:** Application will require MySQL to run. Provide clear startup error if DB is unavailable.
> - **Credentials:** Store `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE` in environment variables (e.g. `.env`). Never commit credentials.
> - **First run:** Schema creation and optional seed (admin user) will run via init script. No automatic migration of existing in-memory data—fresh install assumed.

---

## TDD Strategy

- [ ] **Before** implementing DB layer: Add `tests/test_db.py` with tests for `db.models` (User, Target, Vulnerability, Report) CRUD and `db.queries` helpers.
- [ ] **Before** changing routes: Add `tests/test_routes.py` (or extend existing) with integration tests for `/api/targets` CRUD, `/api/vulnerabilities` list, `/api/dashboard-stats` using a test DB.
- [ ] **After** DB integration: Add test for scan flow → vulnerabilities inserted into DB.

---

## Accessibility Strategy

- No new interactive UI elements. Existing pages (dashboard, targets, vulnerabilities, reports) remain unchanged.
- Ensure any new error messages (e.g. "Database unavailable") are announced to screen readers if displayed in UI.

---

## Proposed Changes

### 1. Database Layer

#### [NEW] `db/__init__.py`
- Initialize Flask app extension (e.g. `mysql-connector-python` or `PyMySQL` with connection pooling).
- Export `get_db()`, `init_db(app)`.

#### [NEW] `db/config.py`
- Read `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE` from `os.environ` (with defaults for local dev).
- Build connection config dict for connector.

#### [NEW] `db/schema.sql`
- `users`: id, email (unique), name, password_hash, role, created_at
- `targets`: id (AUTO_INCREMENT), name, url (unique), type, status, last_scan, scan_count, description, total_vulns, vuln_counts_json (JSON/TEXT), created_at, updated_at
- `scan_history`: id, target_id (FK), scan_time, total, critical, high, medium, low, info, report_filename, runtime_seconds, created_at
- `vulnerabilities`: id (AUTO_INCREMENT), target_id (FK), target_url, scan_date, test, severity, status, finding, vulnerable_path, remediation, resolution_steps, is_fixed, created_at
- `reports`: id (AUTO_INCREMENT), name, target_url, filename, date, status, vuln_counts_json, total, runtime_seconds, scan_time, created_at
- Indexes: `vulnerabilities(target_id)`, `vulnerabilities(severity)`, `vulnerabilities(is_fixed)`, `reports(target_url)`, `scan_history(target_id)`.

#### [NEW] `db/models.py` (or `db/queries.py`)
- Helper functions: `get_user_by_email`, `create_user`, `get_all_targets`, `get_target_by_id`, `get_or_create_target`, `update_target`, `delete_target`, `insert_vulnerabilities`, `get_vulnerabilities` (with filters), `toggle_vulnerability_fixed`, `insert_report`, `get_reports`, `get_report_by_id`, `get_dashboard_stats` (aggregation query), `get_scan_history_for_target`, `insert_scan_history`.

#### [NEW] `db/init_db.py` (or script)
- Create database if not exists, run `schema.sql`, optionally seed admin user.

---

### 2. Application Changes

#### [MODIFY] `app.py`
- Add `from db import init_db, get_db` (or equivalent).
- Call `init_db(app)` at startup; fail fast with clear error if MySQL unreachable.
- Replace `USERS` with `db.get_user_by_email` in `/login`.
- Replace `targets_store`, `targets_counter` with DB calls in:
  - `get_or_create_target`, `api_targets`, `api_target_add`, `api_target_get`, `api_target_update`, `api_target_delete`
- Replace `vulnerabilities_store` with DB calls in:
  - `api_vulnerabilities`, `api_vulnerability_detail`, `api_vulnerability_fix`, `api_dashboard_stats`, `api_target_get`, `api_report_detail`
- Replace `reports_store`, `reports_counter` with DB calls in:
  - `api_reports`, `api_report_detail`, `download_report`
- Replace `rebuild_dashboard_stats` with `db.get_dashboard_stats()`.
- In scan completion flow (`run_scan`): insert vulnerabilities via `db.insert_vulnerabilities`, update target via `db.update_target`, insert scan_history, insert report via `db.insert_report`.
- Remove global `targets_store`, `vulnerabilities_store`, `reports_store`, `targets_counter`, `reports_counter`, `dashboard_stats` (keep `USERS` only if needed for backward compat during transition—otherwise remove).
- Keep `active_scan`, `auth_sessions`, `update_queue`, `scan_results` in-memory (no DB).

---

### 3. Dependencies & Config

#### [MODIFY] `requirements.txt`
- Add `mysql-connector-python` (or `PyMySQL`) and `python-dotenv` (for `.env` loading).

#### [NEW] `.env.example`
- Template: `MYSQL_HOST=localhost`, `MYSQL_USER=root`, `MYSQL_PASSWORD=`, `MYSQL_DATABASE=vapt_db`.

#### [NEW] `.gitignore` (if not exists) or update
- Ensure `.env` is ignored.

---

### 4. Verification Plan

#### Automated Tests
- `pytest tests/` — DB layer unit tests pass; route integration tests pass with test DB.
- Ensure `tests/conftest.py` provides test DB fixture (separate DB or SQLite for speed if preferred for CI).

#### Manual Verification
- [ ] Start MySQL, set `.env`, run `python db/init_db.py` (or equivalent), then `python app.py`.
- [ ] Login with admin credentials.
- [ ] Create target, run scan, verify vulnerabilities and report appear.
- [ ] Restart app; verify targets, vulnerabilities, reports persist.
- [ ] Toggle vulnerability fix; restart; verify status persists.
- [ ] Stop MySQL, start app; verify clear error message (no crash with cryptic traceback).
- [ ] Dashboard stats and charts load correctly from DB.

---

## File Summary

| Action | Path |
|--------|------|
| NEW | `db/__init__.py` |
| NEW | `db/config.py` |
| NEW | `db/schema.sql` |
| NEW | `db/models.py` or `db/queries.py` |
| NEW | `db/init_db.py` |
| NEW | `.env.example` |
| NEW | `tests/test_db.py` |
| NEW | `tests/test_routes.py` (or extend) |
| NEW | `tests/conftest.py` |
| MODIFY | `app.py` |
| MODIFY | `requirements.txt` |
| MODIFY | `.gitignore` |

---

## Execution Order

1. Add dependencies, `.env.example`, `.gitignore`.
2. Create `db/` layer (config, schema, models/queries, init).
3. Add tests for DB layer.
4. Modify `app.py` to use DB (incremental: users → targets → vulnerabilities → reports → dashboard).
5. Add route integration tests.
6. Manual verification.
