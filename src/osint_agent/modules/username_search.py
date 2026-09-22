"""
Username footprinting: checks whether a given username/handle exists across
a curated list of public platforms. Useful for tracing a public-facing
persona, pseudonym, or organizational account across the web.

This checks account *existence* on public platforms only — it does not
scrape profile content or attempt to identify private individuals behind
a handle.
"""
import concurrent.futures
import requests

from ..config import Config

# (platform, url_template, "not found" indicator strategy)
# strategy "404" -> account exists if HTTP 200
# strategy "text" -> account missing if marker text found in body even on 200
PLATFORMS = [
    # Dev / code
    ("GitHub", "https://github.com/{u}", "404"),
    ("GitLab", "https://gitlab.com/{u}", "404"),
    ("Bitbucket", "https://bitbucket.org/{u}/", "404"),
    ("SourceForge", "https://sourceforge.net/u/{u}/", "404"),
    ("Replit", "https://replit.com/@{u}", "404"),
    ("CodePen", "https://codepen.io/{u}", "404"),
    ("HackerOne", "https://hackerone.com/{u}", "404"),
    ("Kaggle", "https://www.kaggle.com/{u}", "404"),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "404"),
    ("npm", "https://www.npmjs.com/~{u}", "404"),
    ("PyPI", "https://pypi.org/user/{u}/", "404"),

    # Major social
    ("Twitter/X", "https://x.com/{u}", "404"),
    ("Instagram", "https://www.instagram.com/{u}/", "404"),
    ("Facebook", "https://www.facebook.com/{u}", "404"),
    ("TikTok", "https://www.tiktok.com/@{u}", "404"),
    ("Snapchat", "https://www.snapchat.com/add/{u}", "404"),
    ("Threads", "https://www.threads.net/@{u}", "404"),
    ("Bluesky", "https://bsky.app/profile/{u}.bsky.social", "404"),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{u}", "404"),
    ("Pinterest", "https://www.pinterest.com/{u}/", "404"),
    ("VK", "https://vk.com/{u}", "404"),

    # Video / streaming / audio
    ("YouTube", "https://www.youtube.com/@{u}", "404"),
    ("Twitch", "https://www.twitch.tv/{u}", "404"),
    ("Vimeo", "https://vimeo.com/{u}", "404"),
    ("SoundCloud", "https://soundcloud.com/{u}", "404"),
    ("Spotify (artist/user)", "https://open.spotify.com/user/{u}", "404"),
    ("Bandcamp", "https://{u}.bandcamp.com", "404"),
    ("Kick", "https://kick.com/{u}", "404"),

    # Forums / Q&A / discussion
    ("Reddit", "https://www.reddit.com/user/{u}/", "404"),
    ("HackerNews", "https://news.ycombinator.com/user?id={u}", "text:No such user"),
    ("Stack Overflow (search)", "https://stackoverflow.com/users?tab=Reputation&filter=all&search={u}", "text:No users matched"),
    ("Quora", "https://www.quora.com/profile/{u}", "404"),
    ("Discord (invite pattern n/a - skip)", None, None),  # placeholder removed below

    # Blogging / writing / publishing
    ("Medium", "https://medium.com/@{u}", "404"),
    ("Substack", "https://{u}.substack.com", "404"),
    ("WordPress.com", "https://{u}.wordpress.com", "404"),
    ("Blogger", "https://{u}.blogspot.com", "404"),
    ("Tumblr", "https://{u}.tumblr.com", "404"),
    ("Dev.to", "https://dev.to/{u}", "404"),
    ("Hashnode", "https://hashnode.com/@{u}", "404"),

    # Professional / business
    ("LinkedIn (company)", "https://www.linkedin.com/company/{u}/", "404"),
    ("AngelList/Wellfound", "https://wellfound.com/u/{u}", "404"),
    ("Crunchbase (person)", "https://www.crunchbase.com/person/{u}", "404"),
    ("Behance", "https://www.behance.net/{u}", "404"),
    ("Dribbble", "https://dribbble.com/{u}", "404"),

    # Messaging
    ("Telegram", "https://t.me/{u}", "404"),
    ("Keybase", "https://keybase.io/{u}", "404"),

    # Creative / niche
    ("DeviantArt", "https://www.deviantart.com/{u}", "404"),
    ("Flickr", "https://www.flickr.com/people/{u}/", "404"),
    ("500px", "https://500px.com/p/{u}", "404"),
    ("ArtStation", "https://www.artstation.com/{u}", "404"),
    ("Itch.io", "https://{u}.itch.io", "404"),
    ("Patreon", "https://www.patreon.com/{u}", "404"),
    ("Ko-fi", "https://ko-fi.com/{u}", "404"),
    ("Steam (custom URL)", "https://steamcommunity.com/id/{u}", "text:The specified profile could not be found"),
    ("Chess.com", "https://www.chess.com/member/{u}", "404"),
    ("Letterboxd", "https://letterboxd.com/{u}/", "404"),
    ("Goodreads (search)", "https://www.goodreads.com/user/show/{u}", "404"),
    ("MyAnimeList", "https://myanimelist.net/profile/{u}", "404"),
    ("Roblox (search hint - skip pattern)", None, None),
]

# Drop unusable placeholder entries (kept above only for documentation of what was considered)
PLATFORMS = [p for p in PLATFORMS if p[1] is not None]


def _check_platform(name, url_template, strategy, username):
    url = url_template.format(u=username)
    headers = {"User-Agent": Config.USER_AGENT}
    result = {"platform": name, "url": url, "status": "unknown"}
    try:
        resp = requests.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT, allow_redirects=True)
        if strategy == "404":
            result["status"] = "found" if resp.status_code == 200 else "not_found"
        elif strategy.startswith("text:"):
            marker = strategy.split("text:", 1)[1]
            result["status"] = "not_found" if marker in resp.text else "found"
        result["http_code"] = resp.status_code
    except requests.RequestException as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result


def run(username: str) -> dict:
    print(f"  [username] Checking '{username}' across {len(PLATFORMS)} platforms...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        futures = [
            executor.submit(_check_platform, name, tmpl, strat, username)
            for name, tmpl, strat in PLATFORMS
        ]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    found = sorted([r for r in results if r["status"] == "found"], key=lambda r: r["platform"])
    not_found = [r for r in results if r["status"] == "not_found"]
    errors = [r for r in results if r["status"] == "error"]

    return {
        "username": username,
        "found": found,
        "not_found_count": len(not_found),
        "errors": errors,
    }
