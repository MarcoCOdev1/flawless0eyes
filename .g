# Copy this file to .env and fill in what you have. Everything is optional
# except that without HIBP_API_KEY, breach-check is skipped, and without a
# Google/Bing key, search falls back to DuckDuckGo HTML (works fine, just
# less robust and can get occasionally rate-limited).

# Have I Been Pwned API key -> https://haveibeenpwned.com/API/Key
HIBP_API_KEY=

# Google Programmable Search Engine -> https://programmablesearchengine.google.com/
GOOGLE_CSE_API_KEY=https://cse.google.com/cse?cx=b1b6b47ccbb5343c8
GOOGLE_CSE_CX=b1b6b47ccbb5343c8

# Bing Web Search API (Azure) -> https://portal.azure.com/
BING_API_KEY=

# Misc tuning
OSINT_USER_AGENT=Mozilla/5.0 (compatible; ResearchAgent/1.0; +investigative-research-tool)
OSINT_TIMEOUT=10
OSINT_MAX_WORKERS=20
