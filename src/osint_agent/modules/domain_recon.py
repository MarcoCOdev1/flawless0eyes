"""
Domain reconnaissance: WHOIS, DNS records, and subdomain enumeration via
certificate transparency logs (crt.sh). All sources are public/passive —
no active scanning of target infrastructure.
"""
import socket
import concurrent.futures
import requests

from ..config import Config

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

try:
    import dns.resolver
except ImportError:
    dns = None


def get_whois(domain: str) -> dict:
    if whois_lib is None:
        return {"error": "python-whois not installed"}
    try:
        w = whois_lib.whois(domain)
        return {
            "registrar": w.get("registrar"),
            "creation_date": _stringify(w.get("creation_date")),
            "expiration_date": _stringify(w.get("expiration_date")),
            "updated_date": _stringify(w.get("updated_date")),
            "name_servers": w.get("name_servers"),
            "org": w.get("org"),
            "country": w.get("country"),
            "emails": w.get("emails"),
        }
    except Exception as e:
        return {"error": str(e)}


def get_dns_records(domain: str) -> dict:
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    if dns is None:
        # Fallback using socket for basic A record only
        try:
            records["A"] = [socket.gethostbyname(domain)]
        except Exception as e:
            records["A"] = [f"error: {e}"]
        records["_note"] = "dnspython not installed; only A record resolved via socket"
        return records

    resolver = dns.resolver.Resolver()
    resolver.timeout = Config.REQUEST_TIMEOUT
    resolver.lifetime = Config.REQUEST_TIMEOUT

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r.to_text()) for r in answers]
        except Exception:
            records[rtype] = []

    return records


def get_subdomains(domain: str, limit: int = 200) -> list:
    """
    Passive subdomain enumeration via crt.sh (Certificate Transparency logs).
    Public data — no interaction with the target's own infrastructure.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": Config.USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT + 10)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain):
                    subdomains.add(name)
        return sorted(subdomains)[:limit]
    except Exception as e:
        return [f"error: {e}"]


def _resolves(fqdn: str) -> bool:
    try:
        socket.gethostbyname(fqdn)
        return True
    except socket.error:
        return False


def brute_force_subdomains(domain: str, wordlist_path: str) -> list:
    """
    Active DNS resolution check against a wordlist of candidate subdomain
    prefixes (e.g. dev, staging, vpn, admin). Only resolves DNS — does not
    connect to any discovered host. Complements the passive crt.sh lookup
    for names that never appeared in a certificate.
    """
    try:
        with open(wordlist_path) as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    except Exception as e:
        return [f"error: could not read wordlist: {e}"]

    candidates = [f"{w}.{domain}" for w in words]
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        future_map = {executor.submit(_resolves, c): c for c in candidates}
        for future in concurrent.futures.as_completed(future_map):
            if future.result():
                found.append(future_map[future])

    return sorted(found)


def run(domain: str, wordlist_path: str = None) -> dict:
    print(f"  [domain] WHOIS lookup for {domain}...")
    whois_data = get_whois(domain)
    print(f"  [domain] DNS records for {domain}...")
    dns_data = get_dns_records(domain)
    print(f"  [domain] Enumerating subdomains via crt.sh...")
    subdomains = set(get_subdomains(domain))

    brute_forced = []
    if wordlist_path:
        print(f"  [domain] Brute-forcing subdomains with wordlist: {wordlist_path}...")
        brute_forced = brute_force_subdomains(domain, wordlist_path)
        subdomains.update(brute_forced)

    subdomains = sorted(s for s in subdomains if not str(s).startswith("error"))

    return {
        "domain": domain,
        "whois": whois_data,
        "dns": dns_data,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "brute_force_hits": brute_forced,
    }


def _stringify(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value) if value is not None else None
