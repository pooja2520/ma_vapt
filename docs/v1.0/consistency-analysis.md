# Consistency Analysis Report

**Feature:** MySQL Integration  
**Date:** 2025-02-27  
**Artifacts:** Spec → Plan → Tasks (planned)

---

## Summary

**Overall health: GAPS FOUND**

The specification and implementation plan are aligned. The plan covers all user stories and acceptance criteria. A few edge cases and verification tasks need explicit task breakdown when `/tasks` is run.

---

## Current Codebase Baseline (Pre-MySQL)

### In-Memory Data Structures (to be migrated)

| Store | Type | Purpose |
|-------|------|---------|
| `USERS` | dict | User auth (email → name, password_hash, role) |
| `targets_store` | dict | Targets by id |
| `targets_counter` | list | Auto-increment for target IDs |
| `vulnerabilities_store` | list | All vulnerability findings |
| `reports_store` | list | Report metadata |
| `reports_counter` | list | Auto-increment for report IDs |
| `dashboard_stats` | dict | Computed from vulnerabilities |

### Runtime-Only (stay in-memory)

| Store | Purpose |
|-------|---------|
| `active_scan` | Live scan state, logs, progress |
| `auth_sessions` | HTTP session cookies for authenticated scans |
| `update_queue` | SSE event queue |
| `scan_results` | Last scan result for download |

### Data Shapes

**Target:** id, name, url, type, status, last_scan, scan_count, scan_history (list), description, vuln_counts (dict), total_vulns

**Vulnerability:** Test, Severity, Status, Finding, Vulnerable Path, Remediation, Resolution Steps, target_url, scan_date, _fixed

**Report:** id, name, target_url, filename, date, status, vuln_counts, total, runtime_seconds, scan_time

---

## Traceability Matrix

| Spec Item | Plan Section | Task(s) | Status |
|-----------|--------------|---------|--------|
| US1.1, US1.2 | Schema: users table | db/schema.sql, db/models.py | ✅ Aligned |
| US2.1–US2.3 | Schema: targets, scan_history | db/schema.sql | ✅ Aligned |
| US3.1–US3.3 | Schema: vulnerabilities | db/schema.sql | ✅ Aligned |
| US4.1, US4.2 | Schema: reports | db/schema.sql | ✅ Aligned |
| US5.1, US5.2 | Dashboard API | app.py changes | ✅ Aligned |
| AC1–AC6 | Proposed Changes | All routes in app.py | ✅ Aligned |
| AC7 | Verification Plan | Manual check | ✅ Aligned |
| AC8 | Schema + init script | db/init_db.py, db/schema.sql | ✅ Aligned |
| NFR1–NFR4 | Config, connection pool | db/config.py, db/__init__.py | ✅ Aligned |

---

## Gaps Identified

1. **Migration path for existing in-memory data**  
   - Spec does not require migrating existing runtime data on first run.  
   - Plan should clarify: fresh install vs. no migration script for legacy data.

2. **Report file path handling**  
   - If report file is deleted from disk but row exists in DB, download will fail.  
   - Plan mentions "file path stored" but not error handling for missing files.

3. **Vulnerability `_fixed` field**  
   - Current code uses `_fixed` as runtime toggle. Plan maps to `is_fixed` column.  
   - Ensure API responses preserve `_display_status` logic.

4. **Test tasks**  
   - No explicit test file tasks in plan. TDD strategy should add `tests/test_db.py` and `tests/test_routes.py`.

---

## Recommendations

1. **Add migration script (optional)**  
   - If user has data in memory at cutover, provide a one-time script to export to JSON and import to MySQL (or document "fresh start only").

2. **Clarify missing report file behavior**  
   - Return 404 with message "Report file no longer available" when file is missing.

3. **Add test tasks to plan**  
   - Unit tests for DB layer, integration tests for critical routes (targets CRUD, scan → vuln insert).

4. **Document rollback**  
   - How to revert to in-memory mode if MySQL is unavailable (feature flag or env var).
