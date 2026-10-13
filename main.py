import os
import requests
import csv
import time
import re
import json
import html as htmlmod
import unicodedata
import urllib.robotparser
from collections import deque, Counter
from functools import lru_cache
from urllib.parse import urljoin, urlparse, unquote, parse_qs

try:
    import dns.resolver
except ImportError:
    print("Missing dependency: dnspython")
    print("Install it with:  python -m pip install dnspython")
    exit()

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency: beautifulsoup4")
    print("Install it with:  python -m pip install beautifulsoup4")
    exit()

try:
    from mailscout import Scout
    MAILSCOUT_AVAILABLE = True
except ImportError:
    MAILSCOUT_AVAILABLE = False

try:
    from serpapi import GoogleSearch
    SERPAPI_LIB_AVAILABLE = True
except ImportError:
    SERPAPI_LIB_AVAILABLE = False


# ============================================================
# CONFIGURATION
# ============================================================

# Hunter is OPTIONAL. Leave HUNTER_API_KEY unset to run for free.
#   PowerShell:  $env:HUNTER_API_KEY="YOUR_API_KEY"
#   bash/zsh:    export HUNTER_API_KEY="YOUR_API_KEY"
API_KEY = os.getenv("HUNTER_API_KEY")
USE_HUNTER = bool(API_KEY)

HUNTER_URL = "https://api.hunter.io/v2/domain-search"
OUTPUT_FILE = "emails.csv"

# Omkar Cloud "website-email-contact-scraper" hosted API. Optional, free tier
# available. Get a key at https://www.omkar.cloud (100 req/month free) and:
#   PowerShell:  $env:OMKAR_API_KEY="YOUR_API_KEY"
#   bash/zsh:    export OMKAR_API_KEY="YOUR_API_KEY"
# NOTE: verify the auth parameter name against your dashboard/docs once you
# sign up -- the public README doesn't spell out the exact auth scheme, this
# assumes the same "api_key" query param used by Hunter.
OMKAR_API_KEY = os.getenv("OMKAR_API_KEY")
USE_OMKAR = bool(OMKAR_API_KEY)
OMKAR_URL = "https://website-email-contact-scraper.omkar.cloud/contacts"

# SerpApi: run a Google search scoped to the domain to surface contact/about/
# team pages the same-domain crawler didn't reach, then scrape them normally.
# Optional, free tier available. Get a key at https://serpapi.com and:
#   PowerShell:  $env:SERPAPI_API_KEY="YOUR_API_KEY"
#   bash/zsh:    export SERPAPI_API_KEY="YOUR_API_KEY"
# Requires:  python -m pip install google-search-results
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY")
USE_SERPAPI = bool(SERPAPI_API_KEY) and SERPAPI_LIB_AVAILABLE
SERPAPI_MAX_RESULTS = 20

# Probes each candidate mailbox over raw SMTP (via mailscout, or a fallback
# if mailscout isn't installed) before trusting it. Outbound port 25 is
# blocked on most home/cloud networks, so results may just come back UNKNOWN.
#   python -m pip install mailscout
ENABLE_SMTP_VERIFY = True

# Same-domain crawl limits for the free website-scraping step.
MAX_PAGES_PER_DOMAIN = 20
CRAWL_DELAY_SECONDS = 0.4
PRIORITY_KEYWORDS = (
    "contact", "career", "job", "about", "team", "hr",
    "recruit", "hiring", "join", "people",
)

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; JobSearchEmailFinder/1.0; +personal job search tool)"
}

COMMON_EMAIL_PREFIXES = [
    "job", "jobs", "career", "careers", "recruitment", "recruiting",
    "recruiter", "hr", "humanresources", "talent", "talentacquisition",
    "hiring",
]

# Local parts that are mailboxes for a function, not a person. Used so pattern
# inference doesn't mistake "customer.service@" for a first.last address.
ROLE_WORDS = set(COMMON_EMAIL_PREFIXES) | {
    "info", "contact", "hello", "hi", "admin", "support", "sales", "press",
    "media", "office", "team", "enquiries", "inquiries", "mail", "help",
    "billing", "accounts", "marketing", "legal", "security", "privacy",
    "noreply", "no-reply", "webmaster", "service", "services", "general",
    "reception", "feedback", "partners", "customer", "customers", "care",
    "orders", "careers", "newsletter", "abuse", "postmaster", "studio",
}

# Public ATS (applicant tracking system) hosts. Applying through one of these
# usually beats cold-emailing a guessed address.
ATS_HOSTS = {
    "greenhouse.io": "Greenhouse",
    "lever.co": "Lever",
    "ashbyhq.com": "Ashby",
    "workable.com": "Workable",
    "smartrecruiters.com": "SmartRecruiters",
    "bamboohr.com": "BambooHR",
    "recruitee.com": "Recruitee",
    "teamtailor.com": "Teamtailor",
    "myworkdayjobs.com": "Workday",
    "jobvite.com": "Jobvite",
    "breezy.hr": "Breezy HR",
    "applytojob.com": "JazzHR",
}

if ENABLE_SMTP_VERIFY and MAILSCOUT_AVAILABLE:
    _scout = Scout(
        check_variants=False,
        check_prefixes=False,
        check_catchall=True,
        normalize=False,
        num_threads=5,
        smtp_timeout=3,
    )
else:
    _scout = None


# ============================================================
# EMAIL SYNTAX VALIDATION
# ============================================================

EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)

# Things like "logo@2x.png" match the regex but are image/asset names.
ASSET_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "css", "js",
    "map", "woff", "woff2", "ttf", "eot", "mp4", "webm", "pdf",
}


def validate_syntax(email):
    if not email or len(email) > 254:
        return False
    if not re.fullmatch(EMAIL_REGEX, email):
        return False
    local, _, domain = email.rpartition("@")
    if len(local) > 64:
        return False
    return domain.rsplit(".", 1)[-1].lower() not in ASSET_TLDS


# ============================================================
# MX RECORD CHECK (cached per domain)
# ============================================================

@lru_cache(maxsize=256)
def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        if answers:
            return True
    except Exception:
        pass
    return False


# ============================================================
# SMTP-LEVEL VERIFICATION
# Uses mailscout when available (recommended); otherwise falls back to a
# minimal built-in RCPT-TO probe. Both need outbound port 25 to work.
# ============================================================

def _fallback_mx_host(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return str(sorted(answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return None


def _fallback_smtp_probe(email):
    import smtplib
    import socket

    domain = email.split("@", 1)[1]
    mx_host = _fallback_mx_host(domain)
    if not mx_host:
        return "UNKNOWN"

    try:
        with smtplib.SMTP(mx_host, 25, timeout=8) as smtp:
            smtp.helo("example.com")
            smtp.mail("verify@example.com")
            code, _ = smtp.rcpt(email)
            return "ACCEPTED" if code == 250 else "REJECTED"
    except (smtplib.SMTPException, socket.error, OSError):
        return "UNKNOWN"


def smtp_probe(email):
    """Returns 'ACCEPTED', 'REJECTED', or 'UNKNOWN'."""
    if not ENABLE_SMTP_VERIFY:
        return "UNKNOWN"

    if _scout is not None:
        try:
            return "ACCEPTED" if _scout.check_smtp(email) else "REJECTED"
        except Exception:
            return "UNKNOWN"

    return _fallback_smtp_probe(email)


@lru_cache(maxsize=256)
def catch_all_status(domain):
    """Returns 'YES', 'NO', or 'UNKNOWN'."""
    if not ENABLE_SMTP_VERIFY:
        return "UNKNOWN"

    if _scout is not None:
        try:
            return "YES" if _scout.check_email_catchall(domain) else "NO"
        except Exception:
            return "UNKNOWN"

    import random
    import string
    probe_local = "".join(random.choices(string.ascii_lowercase, k=20))
    return {"ACCEPTED": "YES", "REJECTED": "NO", "UNKNOWN": "UNKNOWN"}[
        _fallback_smtp_probe(f"{probe_local}@{domain}")
    ]


# ============================================================
# EMAIL DE-OBFUSCATION
# Handles the tricks sites use to hide addresses from simple scrapers:
#   - Cloudflare "email protection" (data-cfemail / /cdn-cgi/l/email-protection#)
#   - "name [at] company [dot] com", "(at)", "{at}", "name at company dot com"
#   - percent-encoded mailto links and HTML entities (&#64;)
# ============================================================

def decode_cfemail(encoded):
    """Decode a Cloudflare-protected email (hex string, first byte is the XOR key)."""
    try:
        key = int(encoded[:2], 16)
        return "".join(
            chr(int(encoded[i:i + 2], 16) ^ key) for i in range(2, len(encoded), 2)
        )
    except (ValueError, TypeError):
        return None


_BRACKET_AT = re.compile(r"\s*[\[\(\{]\s*at\s*[\]\)\}]\s*", re.I)
_BRACKET_DOT = re.compile(r"\s*[\[\(\{]\s*dot\s*[\]\)\}]\s*", re.I)
_WORD_OBF = re.compile(
    r"\b([A-Za-z0-9._%+-]+)\s+at\s+([A-Za-z0-9-]+(?:\s+dot\s+[A-Za-z0-9-]+)+)\b",
    re.I,
)
_DOT_WORD = re.compile(r"\s+dot\s+", re.I)


def _join_word_obf(match):
    return f"{match.group(1)}@{_DOT_WORD.sub('.', match.group(2))}"


def deobfuscate_text(text):
    """Rewrite 'name [at] x [dot] com' style text into normal addresses."""
    text = _BRACKET_AT.sub("@", text)
    text = _BRACKET_DOT.sub(".", text)
    return _WORD_OBF.sub(_join_word_obf, text)


def _walk_json_for_email(node):
    """Yield every value stored under an 'email' key in a JSON-LD structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() == "email":
                if isinstance(value, str):
                    yield value
                elif isinstance(value, list):
                    for v in value:
                        if isinstance(v, str):
                            yield v
            else:
                yield from _walk_json_for_email(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_json_for_email(item)


# ============================================================
# WEBSITE CRAWLING (free, no API key needed)
# Same-domain, robots.txt-aware, depth-limited crawl that follows the
# site's own links instead of guessing a fixed list of paths.
# Pages whose URL looks contact/career/HR-related are crawled first.
# ============================================================

def get_robot_parser(domain, scheme):
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(f"{scheme}://{domain}/robots.txt")
    try:
        rp.read()
    except Exception:
        rp = None
    return rp


def fetch_page(session, url):
    try:
        resp = session.get(url, headers=REQUEST_HEADERS, timeout=10)
        if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
            return resp.text
    except requests.RequestException:
        pass
    return None


def fetch_text(session, url):
    """Fetch a plain-text resource (e.g. security.txt). Returns text or None."""
    try:
        resp = session.get(url, headers=REQUEST_HEADERS, timeout=10)
        ctype = resp.headers.get("Content-Type", "")
        if resp.status_code == 200 and ("text/plain" in ctype or "text/" in ctype):
            # Some sites return an HTML 200 "soft 404" -- reject those.
            if "<html" in resp.text[:500].lower():
                return None
            return resp.text
    except requests.RequestException:
        pass
    return None


def extract_emails_from_html(html):
    """Returns (set_of_emails, soup). Looks well beyond visible text."""
    found = set()
    soup = BeautifulSoup(html, "html.parser")

    def add(addr):
        addr = (addr or "").strip().strip(".,;:<>()[]\"'").lower()
        if validate_syntax(addr):
            found.add(addr)

    # 1. mailto: links (percent-decoded, may list several addresses) and
    #    Cloudflare-protected links.
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.lower().startswith("mailto:"):
            for part in unquote(href[len("mailto:"):].split("?", 1)[0]).split(","):
                add(part)
        elif "email-protection#" in href:
            add(decode_cfemail(href.split("#", 1)[1]))

    # 2. Cloudflare data-cfemail attribute (the <span class="__cf_email__"> form).
    for tag in soup.find_all(attrs={"data-cfemail": True}):
        add(decode_cfemail(tag["data-cfemail"]))

    # 3. JSON-LD structured data ("email" / contactPoint.email).
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or script.get_text() or "")
        except ValueError:
            continue
        for value in _walk_json_for_email(data):
            add(value.replace("mailto:", ""))

    # 4. <meta> tags (some sites put a contact address in content="...").
    for meta in soup.find_all("meta", content=True):
        for match in EMAIL_REGEX.findall(meta["content"]):
            add(match)

    # 5. Visible text, plain and de-obfuscated ("name [at] site [dot] com").
    visible = soup.get_text(" ")
    for match in EMAIL_REGEX.findall(visible):
        add(match)
    for match in EMAIL_REGEX.findall(deobfuscate_text(visible)):
        add(match)

    # 6. Raw HTML with entities decoded (&#64; -> @), which also catches
    #    addresses inside inline scripts and attributes. JSON ">"-style
    #    escapes are blanked first so they can't glue onto an address.
    raw = re.sub(r"\\u[0-9a-fA-F]{4}", " ", htmlmod.unescape(html))
    for match in EMAIL_REGEX.findall(raw):
        add(match)

    return found, soup


def extract_all_links(soup, base_url):
    """All absolute http(s) links on a page (any host)."""
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urljoin(base_url, href)
        if urlparse(full).scheme in ("http", "https"):
            links.add(full.split("#")[0])
    for tag in soup.find_all(["iframe", "script"], src=True):
        full = urljoin(base_url, tag["src"].strip())
        if urlparse(full).scheme in ("http", "https"):
            links.add(full.split("#")[0])
    return links


def is_same_domain(url, domain):
    host = urlparse(url).netloc.lower().split(":")[0]
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def extract_same_domain_links(soup, base_url, domain):
    return {u for u in extract_all_links(soup, base_url) if is_same_domain(u, domain)}


def parse_security_txt(text):
    """Pull addresses from 'Contact:' lines of a security.txt."""
    found = set()
    for line in text.splitlines():
        if line.lower().startswith("contact:"):
            value = line.split(":", 1)[1].strip()
            if value.lower().startswith("mailto:"):
                value = value[len("mailto:"):]
            value = unquote(value.split("?", 1)[0])
            if validate_syntax(value.lower()):
                found.add(value.lower())
    return found


def scrape_site_for_emails(domain, max_pages=MAX_PAGES_PER_DOMAIN):
    """Returns (found, ats_links): found maps email -> source url."""
    found = {}  # email -> source url
    ats_links = set()
    session = requests.Session()

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}/"
        home_html = fetch_page(session, base_url)
        if home_html is not None:
            break
    else:
        return found, ats_links  # site unreachable on both schemes

    robots = get_robot_parser(domain, scheme)

    visited = set()
    queue = deque([base_url])
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        # Prioritize contact/career-looking URLs already in the queue.
        queue = deque(sorted(
            queue,
            key=lambda u: 0 if any(k in u.lower() for k in PRIORITY_KEYWORDS) else 1
        ))

        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        if robots is not None:
            try:
                if not robots.can_fetch(REQUEST_HEADERS["User-Agent"], url):
                    continue
            except Exception:
                pass

        html = home_html if (url == base_url and pages_crawled == 0) else fetch_page(session, url)
        pages_crawled += 1
        if html is None:
            continue

        emails, soup = extract_emails_from_html(html)
        for addr in emails:
            found.setdefault(addr, url)

        for link in extract_all_links(soup, url):
            if is_same_domain(link, domain):
                if link not in visited:
                    queue.append(link)
            elif detect_ats_name(link):
                ats_links.add(link)

        time.sleep(CRAWL_DELAY_SECONDS)

    # security.txt: a real, intentionally published contact (usually a
    # security contact rather than HR, so it's labeled with its own source).
    for path in ("/.well-known/security.txt", "/security.txt"):
        text = fetch_text(session, f"{scheme}://{domain}{path}")
        if text:
            for addr in parse_security_txt(text):
                found.setdefault(addr, f"{scheme}://{domain}{path}")
            break

    return found, ats_links


# ============================================================
# EMAIL PATTERN INFERENCE
# If the crawl found jane.doe@company.com, the company probably uses
# first.last@ -- so a named recruiter's address can be guessed.
# Only separator-based patterns can be inferred from addresses alone:
# "jdoe@" could be flast, "jane@" could be first -- both are ambiguous
# without knowing the person's real name.
# ============================================================

PATTERNS = {
    "first.last": lambda f, l: f"{f}.{l}",
    "first_last": lambda f, l: f"{f}_{l}",
    "first-last": lambda f, l: f"{f}-{l}",
    "f.last": lambda f, l: f"{f[0]}.{l}",
    "flast": lambda f, l: f"{f[0]}{l}",
    "firstlast": lambda f, l: f"{f}{l}",
    "first": lambda f, l: f,
    "firstl": lambda f, l: f"{f}{l[0]}",
    "last": lambda f, l: l,
}

# Tried (in order) when no pattern could be inferred from the site.
DEFAULT_GUESS_ORDER = ["first.last", "flast", "first", "firstlast"]


def classify_local(local):
    """Return the pattern name a local part looks like, or None."""
    local = local.lower()
    parts = re.split(r"[._-]", local)
    if any(p in ROLE_WORDS for p in parts) or local in ROLE_WORDS:
        return None
    if re.fullmatch(r"[a-z]{2,}\.[a-z]{2,}", local):
        return "first.last"
    if re.fullmatch(r"[a-z]{2,}_[a-z]{2,}", local):
        return "first_last"
    if re.fullmatch(r"[a-z]{2,}-[a-z]{2,}", local):
        return "first-last"
    if re.fullmatch(r"[a-z]\.[a-z]{2,}", local):
        return "f.last"
    return None


def infer_email_pattern(emails, domain):
    """Returns (pattern, count, example_email) or None."""
    counts = Counter()
    example = {}
    for e in emails:
        local, _, d = e.lower().partition("@")
        if d != domain.lower():
            continue
        p = classify_local(local)
        if p:
            counts[p] += 1
            example.setdefault(p, e)
    if not counts:
        return None
    pattern, n = counts.most_common(1)[0]
    return pattern, n, example[pattern]


def normalize_name(full_name):
    """'José  Álvarez-Smith' -> ('jose', 'alvarezsmith'); None if < 2 words."""
    folded = unicodedata.normalize("NFKD", full_name)
    folded = "".join(c for c in folded if not unicodedata.combining(c)).lower()
    tokens = [re.sub(r"[^a-z]", "", t) for t in folded.split()]
    tokens = [t for t in tokens if t]
    if len(tokens) < 2:
        return None
    return tokens[0], tokens[-1]


def build_candidate(first, last, pattern, domain):
    return f"{PATTERNS[pattern](first, last)}@{domain}"


# ============================================================
# ATS (APPLICANT TRACKING SYSTEM) DETECTION
# Many companies publish openings on Greenhouse / Lever / Ashby etc., and
# those expose public JSON feeds. Applying there beats a cold email.
# ============================================================

def detect_ats_name(url):
    host = urlparse(url).netloc.lower().split(":")[0]
    for suffix, name in ATS_HOSTS.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def _ats_slug(name, url):
    """Extract the company slug from a Greenhouse/Lever/Ashby board URL."""
    parsed = urlparse(url)
    if name == "Greenhouse":
        q = parse_qs(parsed.query)
        if q.get("for"):
            return q["for"][0]
    parts = [p for p in parsed.path.split("/") if p]
    if parts and parts[0] not in ("embed",):
        return parts[0]
    return None


def fetch_ats_jobs(name, url):
    """Return a list of (title, job_url) from a public ATS feed, or []."""
    slug = _ats_slug(name, url)
    if not slug:
        return []

    try:
        if name == "Greenhouse":
            r = requests.get(
                f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs",
                headers=REQUEST_HEADERS, timeout=15)
            if r.status_code == 200:
                return [(j.get("title", ""), j.get("absolute_url", ""))
                        for j in r.json().get("jobs", [])]
        elif name == "Lever":
            r = requests.get(
                f"https://api.lever.co/v0/postings/{slug}?mode=json",
                headers=REQUEST_HEADERS, timeout=15)
            if r.status_code == 200:
                return [(j.get("text", ""), j.get("hostedUrl", ""))
                        for j in r.json()]
        elif name == "Ashby":
            r = requests.get(
                f"https://api.ashbyhq.com/posting-api/job-board/{slug}",
                headers=REQUEST_HEADERS, timeout=15)
            if r.status_code == 200:
                return [(j.get("title", ""), j.get("jobUrl", ""))
                        for j in r.json().get("jobs", [])]
    except (requests.RequestException, ValueError):
        pass
    return []


# ============================================================
# HUNTER DOMAIN SEARCH (only used if USE_HUNTER is True)
# ============================================================

def hunter_search(domain):
    offset = 0
    limit = 10
    results_found = []
    retry_wait = 5

    while True:
        params = {"domain": domain, "api_key": API_KEY, "limit": limit, "offset": offset}

        try:
            response = requests.get(HUNTER_URL, params=params, timeout=30)
        except requests.RequestException as e:
            print(f"Hunter request failed: {e}")
            break

        if response.status_code == 429:
            print(f"Rate limited by Hunter. Waiting {retry_wait}s...")
            time.sleep(retry_wait)
            retry_wait = min(retry_wait * 2, 60)
            continue

        if response.status_code != 200:
            print(f"Hunter API error: {response.status_code}")
            try:
                print(response.json())
            except Exception:
                print(response.text)
            break

        retry_wait = 5
        data = response.json()
        emails = data.get("data", {}).get("emails", [])

        if not emails:
            break

        results_found.extend(emails)

        if len(emails) < limit:
            break

        offset += limit
        time.sleep(0.5)

    return results_found


# ============================================================
# OMKAR CLOUD CONTACT SCRAPER (hosted API, optional)
# ============================================================

def omkar_search(domain):
    """Returns a list of email dicts: {value, sources}."""
    try:
        response = requests.get(
            OMKAR_URL,
            params={"website": domain, "api_key": OMKAR_API_KEY},
            timeout=60,  # their docs note a response can take up to ~2 min
        )
    except requests.RequestException as e:
        print(f"Omkar Cloud request failed: {e}")
        return []

    if response.status_code != 200:
        print(f"Omkar Cloud API error: {response.status_code}")
        try:
            print(response.json())
        except Exception:
            print(response.text)
        return []

    try:
        data = response.json()
    except Exception:
        print("Omkar Cloud: could not parse response as JSON")
        return []

    if data.get("error"):
        print(f"Omkar Cloud: {data['error']}")

    return data.get("emails", [])


# ============================================================
# SERPAPI PAGE DISCOVERY (Google search -> candidate pages -> scrape)
# ============================================================

def serpapi_discover_pages(domain, max_results=SERPAPI_MAX_RESULTS):
    """Returns a set of candidate page URLs found via Google search."""
    urls = set()
    query = (
        f"site:{domain} "
        f"(inurl:contact OR inurl:about OR inurl:team OR inurl:careers "
        f"OR inurl:jobs OR inurl:hr)"
    )
    try:
        search = GoogleSearch({
            "engine": "google",
            "q": query,
            "num": max_results,
            "api_key": SERPAPI_API_KEY,
        })
        results = search.get_dict()
    except Exception as e:
        print(f"SerpApi request failed: {e}")
        return urls

    if "error" in results:
        print(f"SerpApi error: {results['error']}")
        return urls

    for item in results.get("organic_results", []):
        link = item.get("link")
        if link:
            urls.add(link)

    return urls


# ============================================================
# CSV SETUP
# ============================================================

FIELDNAMES = [
    "domain", "email", "first_name", "last_name", "position", "department",
    "type", "confidence", "source", "syntax", "mx", "catch_all", "status"
]


def normalize_field(value):
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v)
    return value or ""


def email_type(email):
    return "generic" if email.split("@")[0] in COMMON_EMAIL_PREFIXES else "personal"


def make_row(domain, email, source, status, catch_all, *, first_name="",
             last_name="", position="", department="", type_=None,
             confidence="", syntax="VALID", mx=None):
    if mx is None:
        mx = "FOUND" if check_mx(email.split("@", 1)[1]) else "NOT_FOUND"
    return {
        "domain": domain, "email": email,
        "first_name": first_name, "last_name": last_name,
        "position": position, "department": department,
        "type": type_ or email_type(email),
        "confidence": confidence, "source": source,
        "syntax": syntax, "mx": mx, "catch_all": catch_all, "status": status,
    }


# ============================================================
# MAIN
# ============================================================

def main():
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=FIELDNAMES).writeheader()

    existing_emails = set()
    try:
        with open(OUTPUT_FILE, "r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                email = row.get("email", "").strip().lower()
                if email:
                    existing_emails.add(email)
    except Exception:
        pass

    print()
    print(f"Hunter.io lookups: {'ENABLED' if USE_HUNTER else 'DISABLED (no HUNTER_API_KEY set -- running free)'}")
    print(f"SMTP verification: {'ENABLED' if ENABLE_SMTP_VERIFY else 'DISABLED (guesses will be labeled UNVERIFIED)'}")
    if ENABLE_SMTP_VERIFY and not MAILSCOUT_AVAILABLE:
        print("  (mailscout not installed -- using a minimal built-in fallback. "
              "Run: python -m pip install mailscout)")
    print(f"Omkar Cloud lookups: {'ENABLED' if USE_OMKAR else 'DISABLED (no OMKAR_API_KEY set)'}")
    if bool(os.getenv('SERPAPI_API_KEY')) and not SERPAPI_LIB_AVAILABLE:
        print("SerpApi discovery: DISABLED (SERPAPI_API_KEY set, but 'google-search-results' "
              "isn't installed -- run: python -m pip install google-search-results)")
    else:
        print(f"SerpApi discovery: {'ENABLED' if USE_SERPAPI else 'DISABLED (no SERPAPI_API_KEY set)'}")

    while True:
        print()
        domain = input("Domain: ").strip()

        if domain.lower() in ["exit", "quit", "q"]:
            print("\nExiting...")
            break
        if not domain:
            continue

        domain = domain.replace("https://", "").replace("http://", "").replace("www.", "").rstrip("/")

        print()
        print(f"Searching: {domain}")
        print()

        print("Checking domain MX records...")
        domain_has_mx = check_mx(domain)
        print("MX: FOUND" if domain_has_mx else "MX: NOT FOUND")

        ca_status = catch_all_status(domain) if domain_has_mx else "UNKNOWN"
        if ENABLE_SMTP_VERIFY and domain_has_mx:
            print(f"Catch-all domain: {ca_status}")

        domain_results = []
        seen_this_domain = set()  # every address seen for this domain, even if already saved

        # ----------------------------------------------------
        # 1. CRAWL THE COMPANY'S OWN SITE (highest confidence, free)
        #    Includes de-obfuscation, JSON-LD, meta tags, security.txt
        # ----------------------------------------------------
        print()
        print(f"Crawling company website (up to {MAX_PAGES_PER_DOMAIN} pages)...")
        scraped, ats_links = scrape_site_for_emails(domain)

        for email, source_url in scraped.items():
            seen_this_domain.add(email)
            if email in existing_emails:
                continue

            result_domain = email.split("@", 1)[1]
            is_sectxt = "security.txt" in source_url
            domain_results.append(make_row(
                domain, email,
                f"{'security.txt' if is_sectxt else 'Website'} ({source_url})",
                "FOUND_ON_SECURITY_TXT" if is_sectxt else "FOUND_ON_SITE",
                ca_status if result_domain == domain else "UNKNOWN",
            ))
            existing_emails.add(email)

        print(f"Found {len(scraped)} email(s) published on the site.")

        # ----------------------------------------------------
        # 1b. ATS DETECTION -- often a better route than any email
        # ----------------------------------------------------
        ats_found = {}
        for link in sorted(ats_links):
            name = detect_ats_name(link)
            ats_found.setdefault(name, link)

        if ats_found:
            print()
            print("Applicant tracking system(s) linked from the site:")
            for name, link in ats_found.items():
                print(f"  {name}: {link}")
                jobs = fetch_ats_jobs(name, link)
                if jobs:
                    print(f"    {len(jobs)} open role(s) in the public feed:")
                    for title, job_url in jobs[:15]:
                        print(f"      - {title}  {job_url}")
                    if len(jobs) > 15:
                        print(f"      ... and {len(jobs) - 15} more")
            print("  Tip: applying through the ATS usually works better than emailing.")

        # ----------------------------------------------------
        # 2. HUNTER (optional)
        # ----------------------------------------------------
        if USE_HUNTER:
            print()
            print("Searching Hunter...")

            for item in hunter_search(domain):
                email = item.get("value", "").strip().lower()
                if not email:
                    continue
                seen_this_domain.add(email)
                if email in existing_emails:
                    continue

                domain_results.append(make_row(
                    domain, email, "Hunter", "FROM_HUNTER", ca_status,
                    first_name=normalize_field(item.get("first_name")),
                    last_name=normalize_field(item.get("last_name")),
                    position=normalize_field(item.get("position")),
                    department=normalize_field(item.get("department")),
                    type_=normalize_field(item.get("type")),
                    confidence=item.get("confidence", ""),
                    syntax="VALID" if validate_syntax(email) else "INVALID",
                ))
                existing_emails.add(email)

        # ----------------------------------------------------
        # 2b. OMKAR CLOUD CONTACT SCRAPER (optional)
        # ----------------------------------------------------
        if USE_OMKAR:
            print()
            print("Searching Omkar Cloud contact scraper...")

            for item in omkar_search(domain):
                email = item.get("value", "").strip().lower()
                if not email:
                    continue
                seen_this_domain.add(email)
                if email in existing_emails:
                    continue

                sources = item.get("sources", [])
                domain_results.append(make_row(
                    domain, email,
                    "Omkar Cloud (" + ", ".join(sources[:1]) + ")" if sources else "Omkar Cloud",
                    "FROM_OMKAR", ca_status,
                    syntax="VALID" if validate_syntax(email) else "INVALID",
                ))
                existing_emails.add(email)

        # ----------------------------------------------------
        # 2c. SERPAPI PAGE DISCOVERY (optional)
        # ----------------------------------------------------
        if USE_SERPAPI:
            print()
            print("Discovering additional pages via SerpApi...")
            discovered_urls = serpapi_discover_pages(domain)
            print(f"Found {len(discovered_urls)} candidate page(s) via search.")

            session = requests.Session()
            for url in discovered_urls:
                if not is_same_domain(url, domain):
                    continue  # stay on the same company, ignore off-site hits

                html = fetch_page(session, url)
                if not html:
                    continue

                emails_here, _ = extract_emails_from_html(html)
                for email in emails_here:
                    seen_this_domain.add(email)
                    if email in existing_emails:
                        continue

                    result_domain = email.split("@", 1)[1]
                    domain_results.append(make_row(
                        domain, email, f"SerpApi discovery ({url})",
                        "FOUND_VIA_SERPAPI",
                        ca_status if result_domain == domain else "UNKNOWN",
                    ))
                    existing_emails.add(email)

                time.sleep(CRAWL_DELAY_SECONDS)

        # ----------------------------------------------------
        # 3. PATTERN INFERENCE + NAMED CONTACT
        # Learn the company's address format from what we found, then build
        # an address for a specific person (e.g. the hiring manager named
        # in the job posting).
        # ----------------------------------------------------
        print()
        inferred = infer_email_pattern(seen_this_domain | set(existing_emails), domain)
        if inferred:
            pattern, count, example = inferred
            print(f"Email pattern inferred: {pattern}@{domain} "
                  f"(from {count} address(es), e.g. {example})")
        else:
            print("No email pattern could be inferred from this site "
                  "(needs addresses like first.last@).")

        person_count = 0
        if domain_has_mx:
            person = input("Recruiter / hiring manager full name (Enter to skip): ").strip()
            names = normalize_name(person) if person else None
            if person and not names:
                print("Need a first AND last name to build an address -- skipped.")
            elif names:
                first, last = names
                if inferred:
                    patterns_to_try = [inferred[0]]
                    base_status = "PATTERN_INFERRED"
                else:
                    patterns_to_try = DEFAULT_GUESS_ORDER
                    base_status = "UNVERIFIED_GUESS"

                for pattern_name in patterns_to_try:
                    email = build_candidate(first, last, pattern_name, domain)
                    if email in existing_emails or not validate_syntax(email):
                        continue

                    status = base_status
                    if ENABLE_SMTP_VERIFY:
                        probe = smtp_probe(email)
                        if probe == "REJECTED":
                            continue
                        if probe == "ACCEPTED" and ca_status != "YES":
                            status = "VERIFIED"

                    domain_results.append(make_row(
                        domain, email,
                        f"Pattern {pattern_name} applied to '{person}'",
                        status, ca_status, first_name=first, last_name=last,
                        type_="personal", mx="FOUND",
                    ))
                    existing_emails.add(email)
                    person_count += 1
                print(f"Added {person_count} address(es) for {person}.")
        else:
            print("Skipping named-contact step: domain has no MX record.")

        # ----------------------------------------------------
        # 4. COMMON RECRUITMENT PREFIXES (guesses -- honestly labeled)
        # ----------------------------------------------------
        print()
        print("Checking common recruitment addresses...")

        recruitment_count = 0

        if ca_status == "YES":
            print("Skipping guesses: domain accepts mail for ANY address (catch-all),")
            print("so a 'found' guess here would prove nothing.")
        elif not domain_has_mx:
            print("Skipping guesses: domain has no MX record.")
        else:
            for prefix in COMMON_EMAIL_PREFIXES:
                email = f"{prefix}@{domain}"
                if email.lower() in existing_emails:
                    continue

                if ENABLE_SMTP_VERIFY:
                    probe = smtp_probe(email)
                    if probe == "REJECTED":
                        continue  # positively confirmed not to exist -- don't save it
                    status = "VERIFIED" if probe == "ACCEPTED" else "UNVERIFIED_GUESS"
                else:
                    status = "UNVERIFIED_GUESS"

                domain_results.append(make_row(
                    domain, email, "Common recruitment address (guess)",
                    status, ca_status, type_="generic", mx="FOUND",
                ))
                existing_emails.add(email)
                recruitment_count += 1

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------
        print()
        print(f"Found {len(domain_results)} new emails")

        if domain_results:
            with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
                csv.DictWriter(f, fieldnames=FIELDNAMES).writerows(domain_results)

        print(f"Saved to: {OUTPUT_FILE}")
        if recruitment_count:
            print(f"Recruitment address guesses added: {recruitment_count}")

        print()
        print("Next Domain: ", end="")


if __name__ == "__main__":
    main()