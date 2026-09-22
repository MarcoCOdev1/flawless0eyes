#!/usr/bin/env python3
"""
osint-agent — a modular OSINT CLI for investigative research.

Usage examples:
    osint-agent domain example.com
    osint-agent domain example.com --wordlist wordlists/subdomains_small.txt
    osint-agent username johndoe_dev
    osint-agent breach someone@example.com
    osint-agent search "acme corp fraud investigation"
    osint-agent entity "Jane Smith Acme Corp"
    osint-agent dork 'site:acme.com filetype:pdf intext:"confidential"'
    osint-agent metadata ./leaked_report.pdf
    osint-agent metadata https://example.com/report.pdf
    osint-agent full example.com --username acme_corp --email press@acme.com

Reports are written to ./reports/<timestamp>_<target>.md and .json in your
current working directory.

Ethical use: build cases from public, passive sources; verify everything
independently before publishing; respect platform terms of service and
applicable law in your jurisdiction. This tool targets organizations,
domains, documents, and public-facing/professional identities — not
private individuals.
"""
import argparse
import os
import re
from datetime import datetime

from .config import Config
from .modules import domain_recon, username_search, breach_check, web_search, entity_search, doc_metadata, report

# Reports land in the user's current directory, not inside the installed package
REPORTS_DIR = os.path.join(os.getcwd(), "reports")


def slugify(text: str) -> str:
    text = re.sub(r"[^\w\-.]+", "_", text.strip())
    return text.strip("_")[:60] or "target"


def cmd_domain(args):
    findings = {"target": args.domain, "domain": domain_recon.run(args.domain, resolve_wordlist(args.wordlist))}
    finish(findings, args.domain, args)


def cmd_username(args):
    findings = {"target": args.username, "username": username_search.run(args.username)}
    finish(findings, args.username, args)


def cmd_breach(args):
    findings = {"target": args.email, "breach": breach_check.run(args.email)}
    finish(findings, args.email, args)


def cmd_search(args):
    findings = {"target": args.query, "search": web_search.run(args.query, args.num)}
    finish(findings, args.query, args)


def cmd_entity(args):
    findings = {"target": args.name, "entity": entity_search.run(args.name, args.num)}
    finish(findings, args.name, args)


def cmd_metadata(args):
    findings = {"target": args.source, "metadata": doc_metadata.run(args.source)}
    finish(findings, args.source, args)


def cmd_full(args):
    findings = {"target": args.domain}
    findings["domain"] = domain_recon.run(args.domain, resolve_wordlist(args.wordlist))
    if args.username:
        findings["username"] = username_search.run(args.username)
    if args.email:
        findings["breach"] = breach_check.run(args.email)
    findings["search"] = web_search.run(args.domain, args.num)
    if args.entity_name:
        findings["entity"] = entity_search.run(args.entity_name, args.num)
    finish(findings, args.domain, args)


def finish(findings: dict, target: str, args):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    basename = f"{timestamp}_{slugify(target)}"

    json_path = report.save_json(findings, REPORTS_DIR, basename)
    md_path = report.save_markdown(findings, REPORTS_DIR, basename)

    print(f"\n✅ Done. Report saved to:")
    print(f"   {md_path}")
    print(f"   {json_path}")


def resolve_wordlist(path: str) -> str:
    """
    Resolve a wordlist path. Supports a plain filesystem path, or the
    shorthand 'built-in:small' to use the wordlist bundled with the package
    (works even when installed via pipx with no local wordlists/ folder).
    """
    if path is None:
        return None
    if path == "built-in:small":
        try:
            import importlib.resources as res
            with res.as_file(res.files("osint_agent") / "wordlists" / "subdomains_small.txt") as p:
                return str(p)
        except Exception:
            return path
    return path


def main():
    parser = argparse.ArgumentParser(
        prog="osint-agent",
        description="osint-agent — modular OSINT CLI for investigative research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version="osint-agent 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("domain", help="WHOIS, DNS, and subdomain recon")
    p.add_argument("domain")
    p.add_argument("--wordlist", help="Path to a wordlist, or 'built-in:small' to use the bundled list")
    p.set_defaults(func=cmd_domain)

    p = sub.add_parser("username", help="Check username existence across platforms")
    p.add_argument("username")
    p.set_defaults(func=cmd_username)

    p = sub.add_parser("breach", help="Check email breach exposure via HIBP")
    p.add_argument("email")
    p.set_defaults(func=cmd_breach)

    p = sub.add_parser("search", help="Web search")
    p.add_argument("query")
    p.add_argument("--num", type=int, default=10)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("entity", help="Structured multi-query search for a name/entity")
    p.add_argument("name")
    p.add_argument("--num", type=int, default=5)
    p.set_defaults(func=cmd_entity)

    p = sub.add_parser("dork", help="Run one hand-crafted search query with full operator support (site:, intext:, filetype:, etc.)")
    p.add_argument("query", help='e.g. \'site:target.com filetype:pdf intext:"confidential"\'')
    p.add_argument("--num", type=int, default=10)
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("metadata", help="Extract metadata from a PDF/image (local path or URL)")
    p.add_argument("source")
    p.set_defaults(func=cmd_metadata)

    p = sub.add_parser("full", help="Run domain + optional username/email/entity modules together")
    p.add_argument("domain")
    p.add_argument("--wordlist", help="Path to a wordlist, or 'built-in:small' to use the bundled list")
    p.add_argument("--username")
    p.add_argument("--email")
    p.add_argument("--entity-name", dest="entity_name")
    p.add_argument("--num", type=int, default=5)
    p.set_defaults(func=cmd_full)

    args = parser.parse_args()

    missing = Config.warn_missing()
    if missing:
        print("⚠️  Note:")
        for m in missing:
            print(f"   - {m}")
        print()

    print(f"🔎 Running: {args.command}\n")
    args.func(args)


if __name__ == "__main__":
    main()
