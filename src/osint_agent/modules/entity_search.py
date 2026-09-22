"""
Name / entity search: runs a structured set of Google-style dork queries
to aggregate what's publicly indexed about a name or organization — news
coverage, filings, professional profiles, documents, and site-specific
mentions across a broad set of platforms.

Uses real search operators (site:, intext:, intitle:, inurl:, filetype:)
for precision. These are interpreted correctly by Google CSE and Bing;
DuckDuckGo's HTML backend honors site:/filetype:/inurl: but has partial/
inconsistent support for intitle:/intext:, so results may vary there —
this is noted in the output.

This aggregates public search-engine results only. It does not scrape
platforms directly, does not bypass any login/paywall, and is meant for
researching organizations and public figures in their public/professional
capacity — not for compiling dossiers on private individuals.
"""
from . import web_search
from ..config import Config

# Each entry: (label, dork template). {q} = quoted exact-match target.
DORK_TEMPLATES = [
    ("General mentions", '{q}'),
    ("Exact phrase in page body", 'intext:{q}'),
    ("Exact phrase in page title", 'intitle:{q}'),
    ("News coverage", '{q} (intext:news OR intext:article OR intext:investigation)'),
    ("Court / legal records", '{q} (intext:lawsuit OR intext:"court filing" OR intext:complaint OR intext:plaintiff)'),
    ("Financial / corporate filings", '{q} (intext:"SEC filing" OR intext:"annual report" OR intext:prospectus OR intext:10-K)'),
    ("Press releases", '{q} (intext:"press release" OR inurl:press-release OR inurl:newsroom)'),
    ("PDF documents", '{q} filetype:pdf'),
    ("Spreadsheets & data files", '{q} (filetype:xlsx OR filetype:csv OR filetype:xls)'),
    ("Presentations", '{q} (filetype:ppt OR filetype:pptx)'),
    ("LinkedIn profiles", 'site:linkedin.com/in {q}'),
    ("LinkedIn companies/posts", 'site:linkedin.com {q}'),
    ("Twitter/X mentions", 'site:x.com {q}'),
    ("Facebook mentions", 'site:facebook.com {q}'),
    ("Instagram mentions", 'site:instagram.com {q}'),
    ("Reddit discussions", 'site:reddit.com {q}'),
    ("GitHub mentions", 'site:github.com {q}'),
    ("Pastebin-style leak sites", '(site:pastebin.com OR site:ghostbin.com) {q}'),
    ("Government / .gov mentions", 'site:*.gov {q}'),
    ("Academic / .edu mentions", 'site:*.edu {q}'),
    ("Wikipedia / Wikidata", '(site:wikipedia.org OR site:wikidata.org) {q}'),
    ("Crunchbase / business databases", 'site:crunchbase.com {q}'),
    ("Job postings mentioning target", '{q} (inurl:careers OR inurl:jobs OR intext:"is hiring")'),
    ("Subdomain/internal doc leakage", '{q} (inurl:internal OR inurl:confidential OR inurl:staging)'),
]


def _quote(term: str) -> str:
    term = term.strip()
    if term.startswith('"') and term.endswith('"'):
        return term
    return f'"{term}"'


def run(name_or_entity: str, num_per_query: int = 5) -> dict:
    quoted = _quote(name_or_entity)
    print(f"  [entity] Running {len(DORK_TEMPLATES)} dork queries for {quoted}...")

    if Config.GOOGLE_CSE_API_KEY and Config.GOOGLE_CSE_CX:
        backend_hint = "google_cse"
    elif Config.BING_API_KEY:
        backend_hint = "bing"
    else:
        backend_hint = "duckduckgo_html"

    results = {}
    for label, template in DORK_TEMPLATES:
        query = template.format(q=quoted)
        outcome = web_search.run(query, num=num_per_query)
        results[label] = outcome

    note = None
    if backend_hint == "duckduckgo_html":
        note = ("Running on DuckDuckGo HTML fallback: site:/filetype:/inurl: operators work reliably, "
                "but intitle:/intext: support is inconsistent — add GOOGLE_CSE_API_KEY/CX or BING_API_KEY "
                "to your .env for full operator support and better precision.")

    return {"target": name_or_entity, "backend": backend_hint, "note": note, "queries": results}
