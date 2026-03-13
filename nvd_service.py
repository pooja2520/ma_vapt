"""
NVD (National Vulnerability Database) Service - Real-time CVE enrichment.
Uses NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limits: 5 req/30s without API key, 50 req/30s with key.
"""
import os
import re
import time
import json
import threading
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# API config
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 86400  # 24 hours
RATE_LIMIT_DELAY = 6.5     # seconds between requests (safe for 5/30s limit)
RATE_LIMIT_DELAY_KEY = 0.7 # with API key

# In-memory cache: { cve_id: (data, timestamp) }
_cache = {}
_cache_lock = threading.Lock()


def _get_api_key():
    return os.environ.get("NVD_API_KEY", "").strip()


def _rate_limit_delay():
    """Sleep between API calls to respect rate limits."""
    delay = RATE_LIMIT_DELAY_KEY if _get_api_key() else RATE_LIMIT_DELAY
    time.sleep(delay)


def _is_valid_cve(cve_id):
    """Validate CVE ID format: CVE-YYYY-NNNNN+"""
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", (cve_id or "").strip(), re.IGNORECASE))


def _extract_cve_data(vuln):
    """Extract useful fields from NVD API vulnerability object."""
    if not vuln or "cve" not in vuln:
        return None
    cve = vuln["cve"]
    out = {
        "id": cve.get("id", ""),
        "description": "",
        "published": "",
        "lastModified": "",
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "references": [],
        "cwe": [],
    }

    # Description (prefer English)
    for d in cve.get("descriptions", []):
        if d.get("lang", "").lower() == "en":
            out["description"] = (d.get("value") or "").strip()
            break
    if not out["description"] and cve.get("descriptions"):
        out["description"] = (cve["descriptions"][0].get("value") or "").strip()

    # Dates
    out["published"] = cve.get("published", "")
    out["lastModified"] = cve.get("lastModified", "")

    # CVSS (prefer v3.1, then v3.0, then v2)
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr and len(arr) > 0:
            m = arr[0]
            cvss_data = m.get("cvssData", {}) or {}
            out["cvss_score"] = cvss_data.get("baseScore")
            out["cvss_severity"] = cvss_data.get("baseSeverity") or cvss_data.get("severity")
            out["cvss_vector"] = cvss_data.get("vectorString")
            break

    # References
    for ref in cve.get("references", [])[:10]:
        url = ref.get("url")
        if url:
            out["references"].append(url)

    # CWE
    for desc in cve.get("weaknesses", []):
        for d in desc.get("description", []):
            if d.get("lang") == "en":
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    out["cwe"].append(val)

    return out


def fetch_cve(cve_id):
    """
    Fetch CVE details from NVD API. Returns dict or None.
    Uses cache and rate limiting.
    """
    cve_id = (cve_id or "").strip()
    if not _is_valid_cve(cve_id):
        return None

    # Normalize: CVE-2014-0224
    cve_id = cve_id.upper() if not cve_id.startswith("CVE") else cve_id

    # Check cache
    with _cache_lock:
        if cve_id in _cache:
            data, ts = _cache[cve_id]
            if time.time() - ts < CACHE_TTL_SECONDS:
                return data
            del _cache[cve_id]

    # Fetch from API
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {"Accept": "application/json"}
    api_key = _get_api_key()
    if api_key:
        headers["apiKey"] = api_key

    try:
        _rate_limit_delay()
        req = Request(url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as e:
        return None

    vulns = body.get("vulnerabilities") or []
    if not vulns:
        return None

    data = _extract_cve_data(vulns[0])
    if data:
        with _cache_lock:
            _cache[cve_id] = (data, time.time())
    return data


def fetch_cves_batch(cve_ids, max_concurrent=3):
    """
    Fetch multiple CVEs with rate limiting. Returns { cve_id: data }.
    """
    result = {}
    seen = set()
    for cve_id in cve_ids:
        cid = (cve_id or "").strip().upper()
        if not cid or cid in seen:
            continue
        seen.add(cid)
        data = fetch_cve(cid)
        if data:
            result[cid] = data
    return result


def enrich_vulnerability(vuln):
    """
    Enrich a vulnerability dict with NVD data if it has a CVE.
    Modifies vuln in place, adds nvd_data key.
    """
    cve = vuln.get("cve")
    if not cve:
        # Try to extract CVE from name or description
        text = f"{vuln.get('name','')} {vuln.get('description','')}"
        m = re.search(r"(CVE-\d{4}-\d{4,})", text, re.IGNORECASE)
        cve = m.group(1) if m else None
    if not cve:
        return vuln
    data = fetch_cve(cve)
    if data:
        vuln["nvd_data"] = data
        if data.get("description") and not vuln.get("description"):
            vuln["description"] = data["description"]
        if data.get("cvss_severity") and not vuln.get("severity"):
            vuln["severity"] = data["cvss_severity"]
        if data.get("cvss_score") is not None:
            vuln["cvss_score"] = data["cvss_score"]
    return vuln


def extract_cves_from_text(text):
    """Extract all CVE IDs from text."""
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text or "", re.IGNORECASE)))
