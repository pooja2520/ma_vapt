"""
Browser-based login API detection using Playwright.
Captures the exact login request URL from network traffic when the user submits the form.
"""
from urllib.parse import urlparse
import json


def _capture_login_api_via_browser(login_url, timeout_ms=15000):
    """
    Use headless browser to navigate to login page, fill form with dummy creds,
    submit, and capture the exact POST request URL + field names from network.
    Returns (username_field, password_field, api_url) or (None, None, None).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None, None, None

    captured = {"url": None, "method": None, "post_data": None}

    def on_request(request):
        if request.method != "POST":
            return
        url = request.url
        parsed_page = urlparse(login_url)
        parsed_req = urlparse(url)
        # Same-origin or same-domain API (exclude CDNs, analytics)
        if parsed_req.netloc != parsed_page.netloc:
            return
        # Skip static assets, common non-login paths
        skip = ("/static", "/assets", ".js", ".css", ".png", ".jpg", "analytics", "gtm", "facebook", "google")
        if any(s in url.lower() for s in skip):
            return
        post_data = request.post_data
        if not post_data:
            return
        # Login requests typically send credentials - check for password-like content
        data_lower = post_data.lower()
        if "password" not in data_lower and "passwd" not in data_lower and "pwd" not in data_lower:
            return
        # Prefer JSON (SPA API) over form-encoded
        if "application/json" in (request.headers.get("content-type") or ""):
            try:
                obj = json.loads(post_data)
                if isinstance(obj, dict) and any(k in obj for k in ("password", "passwd", "pwd")):
                    captured["url"] = url
                    captured["method"] = "json"
                    captured["post_data"] = obj
                    return
            except json.JSONDecodeError:
                pass
        # Form-encoded
        if "password=" in data_lower or "passwd=" in data_lower:
            captured["url"] = url
            captured["method"] = "form"
            # Parse form data
            params = {}
            for part in post_data.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v
            captured["post_data"] = params

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = context.new_page()
            page.on("request", on_request)

            page.goto(login_url, wait_until="load", timeout=timeout_ms)

            # Wait for SPA to hydrate and render login form
            page.wait_for_timeout(3500)

            # Find and fill login inputs
            email_selectors = [
                'input[type="email"]',
                'input[name="email"]',
                'input[id="email"]',
                'input[id="usernameOrEmail"]',
                'input[name="username"]',
                'input[id="username"]',
                'input[placeholder*="mail" i]',
                'input[placeholder*="email" i]',
                'input[type="text"]',
            ]
            password_selectors = [
                'input[type="password"]',
                'input[name="password"]',
                'input[id="password"]',
            ]

            email_field = None
            password_field = None
            for sel in email_selectors:
                try:
                    el = page.locator(sel).first
                    if el.count() > 0 and el.is_visible(timeout=500):
                        name = el.get_attribute("name") or el.get_attribute("id") or "email"
                        el.fill("detect@vapt.test")
                        email_field = name
                        break
                except Exception:
                    continue

            for sel in password_selectors:
                try:
                    el = page.locator(sel).first
                    if el.count() > 0 and el.is_visible(timeout=500):
                        name = el.get_attribute("name") or el.get_attribute("id") or "password"
                        el.fill("DetectTest123!")
                        password_field = name
                        break
                except Exception:
                    continue

            if not password_field:
                browser.close()
                return None, None, None

            if not email_field:
                email_field = "email"

            # Submit: button or form (request captured by on_request)
            submitted = False
            for btn_sel in ['button[type="submit"]', 'input[type="submit"]', 'button:has-text("Login")', 'button:has-text("Sign in")', 'button:has-text("Log in")', '[type="submit"]']:
                try:
                    btn = page.locator(btn_sel).first
                    if btn.count() > 0 and btn.is_visible(timeout=500):
                        btn.click()
                        submitted = True
                        break
                except Exception:
                    continue

            if not submitted:
                try:
                    form = page.locator("form").first
                    if form.count() > 0:
                        form.evaluate("f => f.submit()")
                        submitted = True
                except Exception:
                    pass

            if submitted:
                page.wait_for_timeout(2500)

            url = captured.get("url")
            post_data = captured.get("post_data")
            if url and post_data:
                # Extract field names from captured payload (actual keys sent by frontend)
                if isinstance(post_data, dict):
                    pwd_key = next((k for k in post_data if any(x in k.lower() for x in ("password", "passwd", "pwd"))), "password")
                    user_key = next((k for k in post_data if any(x in k.lower() for x in ("email", "username", "user", "login"))), "email")
                    browser.close()
                    return user_key, pwd_key, url

            browser.close()
            return None, None, None

        except Exception as e:
            try:
                browser.close()
            except Exception:
                pass
            raise e
