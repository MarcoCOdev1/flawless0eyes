"""
Breach exposure check via Have I Been Pwned (HIBP) API v3.

Intended use: checking a domain you are investigating (e.g. "did company X's
staff domain appear in known breaches"), or an email address you have a
legitimate, documented reason to check (e.g. verifying a tip, or your own
sources' operational security). This is NOT a bulk people-search tool and
requires an API key you must obtain and agree to HIBP's terms for.

Get a key at: https://haveibeenpwned.com/API/Key
"""
import requests
from ..config import Config

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def check_email(email: str) -> dict:
    if not Config.HIBP_API_KEY:
        return {"error": "No HIBP_API_KEY configured. Set it in your environment or .env file."}

    headers = {
        "hibp-api-key": Config.HIBP_API_KEY,
        "User-Agent": Config.USER_AGENT,
    }
    url = f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=false"
    try:
        resp = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT)
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "email": email,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses"),
                    }
                    for b in breaches
                ],
            }
        elif resp.status_code == 404:
            return {"email": email, "breach_count": 0, "breaches": []}
        elif resp.status_code == 429:
            return {"error": "Rate limited by HIBP API. Slow down requests."}
        else:
            return {"error": f"HIBP API returned HTTP {resp.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def run(email: str) -> dict:
    print(f"  [breach] Checking breach exposure for {email}...")
    return check_email(email)
