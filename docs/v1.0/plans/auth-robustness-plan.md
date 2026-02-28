# Authentication Robustness – Analysis & Implementation Plan

## 1. Do We Need Separate Auth Types?

**Yes.** Username and password alone are not enough for most sites.

| Auth Type | What It Is | Can We Use Just Username + Password? |
|-----------|------------|--------------------------------------|
| **HTTP Basic** | Server returns 401, client sends `Authorization: Basic base64(user:pass)` | ✅ Yes – username + password is enough |
| **Form-based** | User submits HTML form; server sets session cookie | ❌ No – we need login URL, field names, often CSRF, success detection |
| **HTTPS** | Transport layer (TLS) | N/A – not an auth type; we already support http/https |
| **Bearer / API Key** | `Authorization: Bearer <token>` | ❌ No – needs token, not username/password |

**Conclusion:** Keep Basic and Form as separate types. HTTPS is handled by the URL scheme. Bearer/custom can be added later.

---

## 2. Current Implementation Summary

### Supported Auth Types
- **None** – no auth
- **Basic** – HTTP Basic Auth (username + password)
- **Form** – form-based login (login URL, username, password, field names, success indicator)

### Current Form Auth Flow
1. **test-auth** – POST to login URL with credentials; store cookies in `auth_sessions[target]`
2. **scan** – pass `auth_credentials.session` (cookies) to `create_authenticated_session`
3. **vapt_auto** – creates new `requests.Session`, sets cookies from stored dict

### Key Mismatch
- Form auth during scan uses **stored cookies** from test-auth
- No re-login during scan – if cookies expire or session invalidates, scan fails
- `auth_sessions` is keyed by `target` – `http://example.com` vs `https://example.com` are different keys

---

## 3. Why Form Login Fails for Most Websites

| Cause | Description |
|-------|-------------|
| **Field names** | Sites use `email`, `user`, `j_username`, `account`, `login`, `passwd` – not always `username`/`password` |
| **CSRF tokens** | Many forms require a per-request token; we capture hidden fields but some tokens are dynamic |
| **Form action** | Relative or empty `action` – we must resolve against login page URL |
| **Success detection** | Heuristics (URL change, response differs) fail for SPAs, AJAX, or same-URL login |
| **Target URL mismatch** | `auth_sessions` key: `http://site.com` ≠ `https://site.com` |
| **Cookie scope** | Domain/path/SameSite can block cookies in our session |
| **No re-login** | Scan uses cookies from test-auth; no fresh login when scan starts |
| **JavaScript forms** | Forms rendered or submitted via JS – we only parse static HTML |

---

## 4. Implementation Plan – Making Login Robust

### Phase 1: Quick Wins (Low Effort)

#### 1.1 Normalize Target URL for auth_sessions
- **File:** `app.py`
- **Change:** Use a normalized key: same scheme (prefer https), no trailing slash, lowercase host
- **Effect:** `http://example.com` and `https://example.com` share the same session

#### 1.2 Re-login at Scan Start (Form Auth)
- **File:** `app.py`, `vapt_auto.py`
- **Change:** For form auth, perform login when scan starts instead of relying only on stored cookies
- **Flow:** Pass full auth_data (login_url, username, password, fields) to scan; vapt_auto performs login at crawl start
- **Effect:** Fresh session even if test-auth was long ago or cookies expired

#### 1.3 Auto-detect Field Names from Login Page
- **File:** `app.py` (test-auth), new helper
- **Change:** If user leaves field names empty, fetch login page, parse form with `type="password"`, infer username field (text/email before password)
- **Effect:** Fewer manual field-name guesses

### Phase 2: Form Handling Improvements

#### 2.1 Broader Field Name Detection
- **File:** `app.py`, `vapt_auto.py`
- **Change:** Support common variants: `email`, `user`, `account`, `login`, `j_username`, `j_password`, `passwd`, `pwd`
- **Effect:** Works with more frameworks (Spring, Django, Laravel, etc.)

#### 2.2 Form Action Resolution
- **File:** `app.py` (test-auth)
- **Change:** Resolve form `action` against login page URL; handle empty/relative action
- **Effect:** Correct POST URL for forms with relative actions

#### 2.3 Improved Success Detection
- **File:** `app.py` (test-auth)
- **Change:** Add strategies: cookie presence, redirect to `/dashboard`-like path, absence of "login" in URL
- **Effect:** Better detection for SPAs and same-URL login

### Phase 3: Advanced (Higher Effort)

#### 3.1 CSRF Token Handling
- **File:** `app.py`, `vapt_auto.py`
- **Change:** Fetch login page, extract CSRF from hidden input or meta tag, include in POST
- **Effect:** Works with CSRF-protected forms

#### 3.2 Login at Crawl Start in vapt_auto
- **File:** `vapt_auto.py`
- **Change:** Add `perform_form_login(session, login_url, auth_data)` called at start of `crawl_website` when auth_type is form
- **Effect:** Scan always starts with a fresh login

#### 3.3 Optional: Selenium/Playwright for JS-heavy Logins
- **Scope:** New module, optional dependency
- **Change:** Fallback to headless browser when standard form login fails
- **Effect:** Handles JS-rendered forms, complex flows (e.g. 2FA placeholder)

---

## 5. Proposed Changes (Prioritized)

### Must Have
| # | Change | File(s) | Effort |
|---|--------|---------|--------|
| 1 | Normalize target URL for auth_sessions | `app.py` | Low |
| 2 | Re-login at scan start for form auth | `app.py`, `vapt_auto.py` | Medium |
| 3 | Auto-detect field names when empty | `app.py` | Medium |

### Should Have
| # | Change | File(s) | Effort |
|---|--------|---------|--------|
| 4 | Broader field name fallbacks | `app.py`, `vapt_auto.py` | Low |
| 5 | Form action resolution | `app.py` | Low |
| 6 | Improved success detection | `app.py` | Medium |

### Nice to Have
| # | Change | File(s) | Effort |
|---|--------|---------|--------|
| 7 | CSRF token extraction | `app.py`, `vapt_auto.py` | Medium |
| 8 | Login helper in vapt_auto | `vapt_auto.py` | Medium |

---

## 6. Verification Plan

### Automated Tests
- Add `test_form_auth_field_detection` – verify auto-detect finds username/password fields
- Add `test_auth_session_key_normalization` – verify http/https share session
- Add `test_form_login_at_scan_start` – verify scan performs fresh login

### Manual Verification
- [ ] Basic auth: site with 401 + WWW-Authenticate
- [ ] Form auth: WordPress, Django admin, Spring Security (j_username/j_password)
- [ ] Form auth: site with CSRF token
- [ ] Form auth: same-URL login (no redirect)
- [ ] Target with http vs https – both use same auth session

---

## 7. Summary

| Question | Answer |
|----------|--------|
| **Do we need separate auth types?** | Yes – Basic and Form are different; username+password alone is not enough for form-based sites |
| **HTTPS auth?** | HTTPS is transport, not auth; already supported |
| **Why do most logins fail?** | Field names, CSRF, success detection, target URL mismatch, no re-login at scan start |
| **Top 3 fixes** | 1) Normalize auth_sessions key, 2) Re-login at scan start, 3) Auto-detect field names |

---

## 8. Implementation Status (Completed)

- [x] Normalize target URL for auth_sessions
- [x] Re-login at scan start for form auth (`perform_form_login` in vapt_auto)
- [x] Auto-detect field names when empty (test-auth) + `/api/detect-login-fields`
- [x] Broader field name fallbacks + form action resolution
- [x] Improved success detection (cookies, redirect heuristics)
- [x] "Detect" button on scanning, target-create, target-edit
