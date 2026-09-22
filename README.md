# osint-agent

A modular OSINT command-line tool built for investigative research: domain
recon, username footprinting, breach exposure checks, dorked web search,
entity/name search, and document metadata forensics — all rolled into one
Markdown/JSON report per run.

## Install

**Via pipx (recommended — installs a `flawless0eyes` command, no source checkout needed):**

```bash
pipx install git+https://github.com/YOUR_USERNAME/osint-agent.git
osint-agent --help
```

**Via pip, in a virtualenv:**

```bash
pip install git+https://github.com/MarcoCOdev1/flawless0eyes.git
```

**From source, for development:**

```bash
git clone https://github.com/MarcoCOdev1/flawless0eyes.git
cd flawless0eyes
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

Once installed via pipx/pip, no source directory is needed to run it — same
model as tools like Sherlock. Copy `.env.example` to `.env` in whatever
directory you run `flawless0eyes` from if you want to add API keys (optional,
see below).

## Modules

| Module      | What it does                                                             | Source type |
|-------------|---------------------------------------------------------------------------|-------------|
| `domain`    | WHOIS, DNS records, passive subdomain enumeration (crt.sh), optional wordlist-based subdomain brute-force | Passive + light active (DNS resolution only) |
| `username`  | Checks handle existence across **58 platforms** (dev, social, forums, blogging, creative, professional, gaming) | Passive |
| `breach`    | Email breach exposure via Have I Been Pwned API                          | API (requires key) |
| `search`    | General web search (Google CSE / Bing / DuckDuckGo fallback)             | Public search |
| `entity`    | Runs **24 Google-dork queries** (`site:`, `intext:`, `intitle:`, `inurl:`, `filetype:`) for a name/org — news, filings, court records, leaks, per-platform mentions, doc leakage | Public search |
| `dork`      | Run one hand-crafted query with full operator support                    | Public search |
| `metadata`  | Extracts embedded metadata from PDFs/images (author, software, GPS EXIF, embedded links) | Passive (local file or public URL) |
| `full`      | Runs domain + any combination of username/email/entity in one pass       | Combined |

## Configuration (optional)

Nothing is required to get started — without API keys, search falls back to
DuckDuckGo HTML and breach-check is simply skipped with a warning. To add
keys, copy `.env.example` to `.env` in the directory you run `osint-agent`
from:

```bash
cp .env.example .env   # fill in HIBP_API_KEY / search API keys if you have them
```

## Usage

```bash
# Domain recon
osint-agent domain example.com
osint-agent domain example.com --wordlist built-in:small   # or a path to your own wordlist

# Username footprint
osint-agent username some_handle

# Breach check (needs HIBP_API_KEY)
osint-agent breach press@example.com

# Web search
osint-agent search "acme corp shell company investigation"

# Structured entity/name search (24 dork queries: news, filings, court
# records, per-platform mentions, leaked docs, .gov/.edu, etc.)
osint-agent entity "Jane Smith Acme Corp"

# One hand-crafted dork query with full operator support
osint-agent dork 'site:acme.com filetype:pdf intext:"confidential"'
osint-agent dork 'site:linkedin.com/in intitle:"Acme Corp" intext:"VP Finance"'

# Document metadata forensics
osint-agent metadata ./leaked_report.pdf
osint-agent metadata https://example.com/public_report.pdf

# Everything at once
osint-agent full example.com --username acme_corp --email press@acme.com --entity-name "Acme Corp"
```

Every run writes a timestamped report to `reports/`:
- `reports/<timestamp>_<target>.md` — human-readable
- `reports/<timestamp>_<target>.json` — raw structured data for further processing

## Search operators / dorks

The `entity` and `dork` commands support real Google-style search operators:

| Operator | Meaning | Example |
|---|---|---|
| `site:` | restrict to a domain | `site:linkedin.com/in "Jane Smith"` |
| `intext:` | phrase must appear in page body | `intext:"confidential" site:acme.com` |
| `intitle:` | phrase must appear in page title | `intitle:"Acme Corp" intext:lawsuit` |
| `inurl:` | phrase must appear in the URL | `inurl:press-release "Acme Corp"` |
| `filetype:` | restrict to a file extension | `"Acme Corp" filetype:pdf` |

**Backend compatibility:** Google CSE and Bing honor all operators above.
The no-key DuckDuckGo HTML fallback reliably supports `site:`, `filetype:`,
and `inurl:`, but `intext:`/`intitle:` support is inconsistent — for full
precision, add a `GOOGLE_CSE_API_KEY`/`GOOGLE_CSE_CX` or `BING_API_KEY` to
your `.env`. The tool tells you in its output which backend served each
query so you know how much to trust operator filtering.

## Extending it

Each module in `src/osint_agent/modules/` is a self-contained file with a
`run()` function that returns a plain dict — add a new file and a new
subcommand in `src/osint_agent/cli.py` to bolt on more sources (e.g. a
Shodan/Censys module, a paste-site search, a court records API for your
jurisdiction).

## Ethics & scope

This tool is built for investigating **organizations, domains, public
documents, and public-facing/professional identities** — the standard
toolkit for corporate investigations, disinformation research, and
verifying tips. It intentionally does *not* include bulk people-search,
location tracking, or anything designed to profile private individuals.

A few practical notes:
- All sources here are passive/public except DNS wordlist brute-forcing,
  which only resolves DNS (no connection is made to discovered hosts).
- Respect each platform's Terms of Service — this tool doesn't bypass
  logins, CAPTCHAs, or paywalls.
- Verify everything independently before publishing. Automated OSINT is a
  lead-generation tool, not a source in itself.
- Check your local laws around WHOIS/EXIF/breach-data lookups before use —
  rules vary by jurisdiction (GDPR relevance for EU-connected data, etc).
