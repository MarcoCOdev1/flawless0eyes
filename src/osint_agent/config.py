"""
Configuration loader for the OSINT agent.
Reads API keys / settings from environment variables (optionally via a .env file).
"""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is optional; env vars still work if set another way
    pass


class Config:
    # Have I Been Pwned API key (https://haveibeenpwned.com/API/Key)
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

    # Optional search backends. If neither is set, we fall back to DuckDuckGo HTML (no key needed).
    GOOGLE_CSE_API_KEY = os.getenv("GOOGLE_CSE_API_KEY", "")
    GOOGLE_CSE_CX = os.getenv("GOOGLE_CSE_CX", "")
    BING_API_KEY = os.getenv("BING_API_KEY", "")

    # Generic HTTP settings
    USER_AGENT = os.getenv(
        "OSINT_USER_AGENT",
        "Mozilla/5.0 (compatible; ResearchAgent/1.0; +investigative-research-tool)"
    )
    REQUEST_TIMEOUT = int(os.getenv("OSINT_TIMEOUT", "10"))
    MAX_WORKERS = int(os.getenv("OSINT_MAX_WORKERS", "20"))

    @classmethod
    def warn_missing(cls):
        missing = []
        if not cls.HIBP_API_KEY:
            missing.append("HIBP_API_KEY (breach-check will be skipped)")
        if not (cls.GOOGLE_CSE_API_KEY and cls.GOOGLE_CSE_CX) and not cls.BING_API_KEY:
            missing.append("GOOGLE_CSE_API_KEY/CX or BING_API_KEY (falling back to DuckDuckGo HTML search)")
        return missing
