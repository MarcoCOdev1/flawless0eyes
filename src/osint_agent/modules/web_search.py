"""
Web search module.

Tries, in order of preference:
  1. Google Programmable Search (if GOOGLE_CSE_API_KEY + GOOGLE_CSE_CX set)
  2. Bing Web Search API (if BING_API_KEY set)
  3. DuckDuckGo HTML endpoint (no key required, best-effort scraping)
"""
import requests
from bs4 import BeautifulSoup

from ..config import Config


def _search_google(query, num=10):
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": Config.GOOGLE_CSE_API_KEY,
        "cx": Config.GOOGLE_CSE_CX,
        "q": query,
        "num": min(num, 10),
    }
    resp = requests.get(url, params=params, timeout=Config.REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return [
        {"title": item.get("title"), "url": item.get("link"), "snippet": item.get("snippet")}
        for item in data.get("items", [])
    ]


def _search_bing(query, num=10):
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": Config.BING_API_KEY}
    params = {"q": query, "count": num}
    resp = requests.get(url, headers=headers, params=params, timeout=Config.REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    return [
        {"title": item.get("name"), "url": item.get("url"), "snippet": item.get("snippet")}
        for item in data.get("webPages", {}).get("value", [])
    ]


def _search_duckduckgo(query, num=10):
    url = "https://html.duckduckgo.com/html/"
    headers = {"User-Agent": Config.USER_AGENT}
    resp = requests.post(url, headers=headers, data={"q": query}, timeout=Config.REQUEST_TIMEOUT)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    results = []
    for result in soup.select(".result__body")[:num]:
        title_el = result.select_one(".result__a")
        snippet_el = result.select_one(".result__snippet")
        if title_el:
            results.append({
                "title": title_el.get_text(strip=True),
                "url": title_el.get("href"),
                "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
            })
    return results


def run(query: str, num: int = 10) -> dict:
    print(f"  [search] Querying: {query!r}")
    backend_used = None
    try:
        if Config.GOOGLE_CSE_API_KEY and Config.GOOGLE_CSE_CX:
            backend_used = "google_cse"
            results = _search_google(query, num)
        elif Config.BING_API_KEY:
            backend_used = "bing"
            results = _search_bing(query, num)
        else:
            backend_used = "duckduckgo_html"
            results = _search_duckduckgo(query, num)
    except Exception as e:
        return {"query": query, "backend": backend_used, "error": str(e), "results": []}

    return {"query": query, "backend": backend_used, "results": results}
