import urllib.request
import urllib.error
import socket
import ssl
import http.client
from datetime import datetime


SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

HEADER_WEIGHTS = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-frame-options": 15,
    "x-content-type-options": 10,
    "x-xss-protection": 10,
    "referrer-policy": 10,
    "permissions-policy": 5,
}

GRADE_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (0,  "F"),
]


def _make_request(domain: str) -> tuple[dict, list[str]]:
    domain = domain.strip().rstrip("/")
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        domain,
        headers={"User-Agent": "VaultChainGuard-SecurityAuditor/1.0"},
        method="HEAD"
    )

    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookie_headers = resp.headers.get_all("set-cookie") or []
            return headers, cookie_headers
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()}
        cookie_headers = exc.headers.get_all("set-cookie") or []
        return headers, cookie_headers


def analyze_headers(domain: str) -> dict:
    try:
        headers, cookie_headers = _make_request(domain)
        reachable = True
        error_msg = None
    except urllib.error.URLError as exc:
        headers = {}
        cookie_headers = []
        reachable = False
        error_msg = str(exc.reason)
    except socket.timeout:
        headers = {}
        cookie_headers = []
        reachable = False
        error_msg = "Connection timed out."
    except Exception as exc:
        headers = {}
        cookie_headers = []
        reachable = False
        error_msg = str(exc)

    present = {}
    missing = []
    for h in SECURITY_HEADERS:
        if h in headers:
            present[h] = headers[h]
        else:
            missing.append(h)

    score = sum(HEADER_WEIGHTS.get(h, 0) for h in present)

    cookie_analysis = _analyze_cookies(cookie_headers)
    if cookie_analysis["insecure_cookies"]:
        score = max(0, score - 10)

    grade = _compute_grade(score)

    header_details = []
    for h in SECURITY_HEADERS:
        status = "PRESENT" if h in present else "MISSING"
        value = present.get(h, "—")
        weight = HEADER_WEIGHTS.get(h, 0)
        header_details.append({
            "header": h,
            "status": status,
            "value": value,
            "weight": weight,
        })

    return {
        "domain": domain,
        "reachable": reachable,
        "error": error_msg,
        "timestamp": datetime.now().isoformat(),
        "score": score,
        "grade": grade,
        "present_headers": present,
        "missing_headers": missing,
        "header_details": header_details,
        "cookie_analysis": cookie_analysis,
        "raw_headers": dict(headers),
    }


def _analyze_cookies(cookie_headers: list) -> dict:
    cookies = []
    insecure = []
    for raw in cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        name_value = parts[0]
        name = name_value.split("=")[0].strip()
        flags = [p.lower() for p in parts[1:]]
        has_httponly = any(f == "httponly" for f in flags)
        has_secure = any(f == "secure" for f in flags)
        has_samesite = any(f.startswith("samesite") for f in flags)
        samesite_val = next((f.split("=")[1].strip() if "=" in f else "present"
                             for f in flags if f.startswith("samesite")), None)
        cookie_info = {
            "name": name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite_val,
            "issues": [],
        }
        if not has_httponly:
            cookie_info["issues"].append("Missing HttpOnly flag")
        if not has_secure:
            cookie_info["issues"].append("Missing Secure flag")
        if not has_samesite:
            cookie_info["issues"].append("Missing SameSite flag")
        elif samesite_val and samesite_val.lower() == "none" and not has_secure:
            cookie_info["issues"].append("SameSite=None requires Secure flag")
        cookies.append(cookie_info)
        if cookie_info["issues"]:
            insecure.append(cookie_info)
    return {
        "total_cookies": len(cookies),
        "cookies": cookies,
        "insecure_cookies": insecure,
        "insecure_count": len(insecure),
    }


def _compute_grade(score: int) -> str:
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def simulate_audit(domain: str) -> dict:
    simulated_scenarios = {
        "example.com": {
            "reachable": True,
            "error": None,
            "score": 10,
            "grade": "F",
            "present_headers": {
                "x-xss-protection": "1; mode=block",
            },
            "missing_headers": [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ],
            "header_details": _build_simulated_details({"x-xss-protection": "1; mode=block"}),
            "cookie_analysis": {
                "total_cookies": 2,
                "insecure_count": 2,
                "cookies": [
                    {"name": "session", "httponly": False, "secure": False,
                     "samesite": None, "issues": ["Missing HttpOnly flag", "Missing Secure flag", "Missing SameSite flag"]},
                    {"name": "pref", "httponly": True, "secure": False,
                     "samesite": "Lax", "issues": ["Missing Secure flag"]},
                ],
                "insecure_cookies": [{"name": "session"}, {"name": "pref"}],
            },
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "raw_headers": {},
        },
        "google.com": {
            "reachable": True,
            "error": None,
            "score": 85,
            "grade": "A",
            "present_headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "SAMEORIGIN",
                "x-content-type-options": "nosniff",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "strict-origin-when-cross-origin",
            },
            "missing_headers": ["permissions-policy"],
            "header_details": _build_simulated_details({
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "SAMEORIGIN",
                "x-content-type-options": "nosniff",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "strict-origin-when-cross-origin",
            }),
            "cookie_analysis": {
                "total_cookies": 1,
                "insecure_count": 0,
                "cookies": [
                    {"name": "NID", "httponly": True, "secure": True,
                     "samesite": "None", "issues": []},
                ],
                "insecure_cookies": [],
            },
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "raw_headers": {},
        },
    }

    clean_domain = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    for key, result in simulated_scenarios.items():
        if key in clean_domain:
            return result

    return analyze_headers(domain)


def _build_simulated_details(present: dict) -> list:
    details = []
    for h in SECURITY_HEADERS:
        status = "PRESENT" if h in present else "MISSING"
        value = present.get(h, "—")
        weight = HEADER_WEIGHTS.get(h, 0)
        details.append({"header": h, "status": status, "value": value, "weight": weight})
    return details
