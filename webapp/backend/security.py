"""
Security middleware and utilities for OSINT Agent web application.

Covers:
- Input sanitization with strict allowlists per field type
- Bot/honeypot detection
- XSS prevention utilities
- IP extraction (proxy-safe)
- Rate limit error handler
- Request validation helpers
"""
import re
import ipaddress
from functools import wraps
from flask import request, jsonify, current_app
import markupsafe


# ─── Input Sanitization ───────────────────────────────────────────────────────

# Strict allowlist patterns — reject anything that doesn't match
_PATTERNS = {
    # Domain: letters, digits, hyphens, dots. No special chars.
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    # Username: alphanumeric + limited special chars used by platforms
    "username": re.compile(r"^[a-zA-Z0-9_.\-]{1,100}$"),
    # Email: basic RFC-5321 shape — full validation done by email-validator lib
    "email": re.compile(r"^[^@\s]{1,254}@[^@\s]{1,253}\.[^@\s]{2,}$"),
    # Search query: printable ASCII + basic unicode, no HTML angle brackets or null bytes
    "query": re.compile(r"^[^\x00<>]{1,500}$"),
}

# Absolute length caps (defense in depth)
_MAX_LENGTHS = {
    "domain": 253,
    "username": 100,
    "email": 320,
    "query": 500,
}

# SQL/NoSQL injection keywords to block in any field
_INJECTION_PATTERNS = re.compile(
    r"(--|;|\/\*|\*\/|xp_|exec\s*\(|union\s+select|drop\s+table|insert\s+into"
    r"|delete\s+from|update\s+set|benchmark\s*\(|sleep\s*\(|waitfor\s+delay"
    r"|\bor\b\s+1\s*=\s*1|\band\b\s+1\s*=\s*1|<script|javascript:|data:text)",
    re.IGNORECASE,
)

# Shell injection characters to block
_SHELL_INJECTION = re.compile(r"[`$&|;><\\\x00]")


def sanitize_input(value: str, field_type: str) -> tuple[bool, str]:
    """
    Validate and sanitize a user-supplied string.

    Returns (is_valid, sanitized_value_or_error_message).
    """
    if not isinstance(value, str):
        return False, "Input must be a string"

    # Null-byte check
    if "\x00" in value:
        return False, "Invalid input: null bytes not allowed"

    # Length cap
    max_len = _MAX_LENGTHS.get(field_type, 500)
    if len(value) > max_len:
        return False, f"Input too long (max {max_len} characters)"

    # Strip leading/trailing whitespace
    value = value.strip()
    if not value:
        return False, "Input cannot be empty"

    # Injection detection (applies to all field types)
    if _INJECTION_PATTERNS.search(value):
        return False, "Input contains disallowed patterns"

    if _SHELL_INJECTION.search(value):
        return False, "Input contains disallowed characters"

    # Field-specific pattern check
    pattern = _PATTERNS.get(field_type)
    if pattern and not pattern.match(value):
        return False, f"Invalid {field_type} format"

    return True, value


def escape_html(value: str) -> str:
    """HTML-escape a string (uses markupsafe — same as Jinja2 uses)."""
    return str(markupsafe.escape(value))


# ─── Bot / Honeypot Detection ─────────────────────────────────────────────────

def check_honeypot(form_data: dict) -> bool:
    """
    Returns True if the request looks like a bot.
    Checks for the presence of a honeypot field that real users never fill.
    The honeypot field is named 'website' (classic spam trap name).
    """
    honeypot_value = form_data.get("website", "")
    if honeypot_value:
        current_app.logger.warning(
            f"Honeypot triggered from IP {get_real_ip()} — value: {honeypot_value!r}"
        )
        return True
    return False


def validate_user_agent() -> bool:
    """
    Reject requests with obviously automated or missing User-Agent strings.
    """
    ua = request.headers.get("User-Agent", "")
    if not ua:
        return False
    # Block common scanner/bot user agents
    bot_patterns = re.compile(
        r"(sqlmap|nikto|nmap|masscan|zgrab|python-requests/2\.[01]|curl/[0-7]\.|wget/)",
        re.IGNORECASE,
    )
    if bot_patterns.search(ua):
        return False
    return True


# ─── IP Extraction ────────────────────────────────────────────────────────────

_TRUSTED_PROXIES = {"127.0.0.1", "::1"}


def get_real_ip() -> str:
    """
    Extract the real client IP, respecting X-Forwarded-For only from
    trusted proxies. Prevents IP spoofing via header injection.
    """
    # Only trust X-Forwarded-For if request comes from a trusted proxy
    remote_addr = request.remote_addr or "unknown"
    if remote_addr in _TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # Take the first IP in the chain
            candidate = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return remote_addr


# ─── Request Validation Decorators ────────────────────────────────────────────

def require_json(f):
    """Decorator: reject requests that aren't JSON content-type."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 415
        return f(*args, **kwargs)
    return decorated


def bot_guard(f):
    """Decorator: reject obvious bots/scanners via User-Agent check."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not validate_user_agent():
            current_app.logger.warning(
                f"Bot-like UA blocked from {get_real_ip()}: {request.headers.get('User-Agent', '')!r}"
            )
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


# ─── Rate Limit Error Handler ─────────────────────────────────────────────────

def rate_limit_exceeded_handler(e):
    """Return JSON (not HTML) when rate limit is exceeded."""
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please slow down and try again later.",
        "retry_after": getattr(e, "retry_after", None),
    }), 429


# ─── Security Headers ─────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    ),
}


def apply_security_headers(response):
    """After-request hook to add security headers to every response."""
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    return response
