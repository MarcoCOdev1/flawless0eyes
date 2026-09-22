"""
Server-side configuration for the OSINT Agent web application.
All API keys and secrets are loaded here, server-side only.
They are NEVER returned in any API response or logged.
"""
import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the backend directory
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    # Fallback: also check project root
    load_dotenv()


class Config:
    # ── Flask Core ────────────────────────────────────────────────────────────
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"

    # ── Database ──────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{Path(__file__).parent / 'osint_agent.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # ── JWT Auth ──────────────────────────────────────────────────────────────
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_hex(64)
    JWT_ACCESS_TOKEN_EXPIRES_SECONDS = 15 * 60        # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES_SECONDS = 7 * 24 * 3600  # 7 days
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_COOKIE_SECURE = False        # Set True in production (HTTPS)
    JWT_COOKIE_SAMESITE = "Strict"
    JWT_COOKIE_CSRF_PROTECT = False  # We use SameSite=Strict instead
    JWT_ACCESS_COOKIE_NAME = "osint_access_token"
    JWT_REFRESH_COOKIE_NAME = "osint_refresh_token"

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_HEADERS_ENABLED = True
    RATE_LIMIT_AUTH = os.getenv("RATE_LIMIT_AUTH", "5 per minute")
    RATE_LIMIT_SCAN = os.getenv("RATE_LIMIT_SCAN", "10 per hour")
    MAX_CONCURRENT_SCANS_PER_USER = int(
        os.getenv("MAX_CONCURRENT_SCANS_PER_USER", "2")
    )

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000"
        ).split(",")
    ]

    # ── OSINT API Keys (server-side only) ─────────────────────────────────────
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
    GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
    GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX", "")
    BING_API_KEY = os.getenv("BING_API_KEY", "")

    # ── OSINT HTTP Tuning ─────────────────────────────────────────────────────
    OSINT_USER_AGENT = os.getenv(
        "OSINT_USER_AGENT",
        "Mozilla/5.0 (compatible; ResearchAgent/1.0; +investigative-research-tool)",
    )
    OSINT_TIMEOUT = int(os.getenv("OSINT_TIMEOUT", "15"))
    OSINT_MAX_WORKERS = int(os.getenv("OSINT_MAX_WORKERS", "20"))

    # ── Security ──────────────────────────────────────────────────────────────
    # Account lockout after N consecutive failed logins
    AUTH_MAX_FAILED_ATTEMPTS = 5
    AUTH_LOCKOUT_MINUTES = 15
    # bcrypt work factor
    BCRYPT_LOG_ROUNDS = 12

    @classmethod
    def warn_missing_keys(cls) -> list[str]:
        warnings = []
        if not cls.HIBP_API_KEY:
            warnings.append("HIBP_API_KEY not set — breach checks will be skipped")
        if not (cls.GOOGLE_CSE_API_KEY and cls.GOOGLE_CSE_CX) and not cls.BING_API_KEY:
            warnings.append("No search API key — falling back to DuckDuckGo HTML scraping")
        return warnings

    @classmethod
    def inject_into_env(cls):
        """
        Push config values into os.environ so the existing osint_agent
        modules (which read Config from their own config.py) pick them up.
        """
        os.environ.setdefault("HIBP_API_KEY", cls.HIBP_API_KEY)
        os.environ.setdefault("GOOGLE_CSE_API_KEY", cls.GOOGLE_CSE_API_KEY)
        os.environ.setdefault("GOOGLE_CSE_CX", cls.GOOGLE_CSE_CX)
        os.environ.setdefault("BING_API_KEY", cls.BING_API_KEY)
        os.environ.setdefault("OSINT_USER_AGENT", cls.OSINT_USER_AGENT)
        os.environ.setdefault("OSINT_TIMEOUT", str(cls.OSINT_TIMEOUT))
        os.environ.setdefault("OSINT_MAX_WORKERS", str(cls.OSINT_MAX_WORKERS))
