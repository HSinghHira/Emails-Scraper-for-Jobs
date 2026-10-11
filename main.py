import os
import requests
import csv
import time
import re
import urllib.robotparser
from collections import deque
from functools import lru_cache
from urllib.parse import urljoin, urlparse

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

# SerpApi (used the way the "clauneck" gem uses it): run a Google search
# scoped to the domain to surface contact/about/team pages the same-domain
# crawler didn't reach (e.g. pages on a different subdomain, or ones your
# crawl depth/page cap missed), then scrape those pages the normal way.
# Optional, free tier available. Get a key at https://serpapi.com and:
#   PowerShell:  $env:SERPAPI_API_KEY="YOUR_API_KEY"
#   bash/zsh:    export SERPAPI_API_KEY="YOUR_API_KEY"
# Requires:  python -m pip install google-search-results
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY")
USE_SERPAPI = bool(SERPAPI_API_KEY) and SERPAPI_LIB_AVAILABLE
SERPAPI_MAX_RESULTS = 20

# Probes each candidate mailbox over raw SMTP (via mailscout, or a fallback
# if mailscout isn't installed) before trusting it. Off by default: outbound
# port 25 is blocked on most home/cloud networks, so results may just come
# back UNKNOWN. Install mailscout for the best version of this check:
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


def validate_syntax(email):
    if not email:
        return False
    return bool(re.fullmatch(EMAIL_REGEX, email))


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
    import random
    import string

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
# WEBSITE CRAWLING (free, no API key needed)
# Same-domain, robots.txt-aware, depth-limited crawl that follows the
# site's own links instead of guessing a fixed list of paths -- so it
# also catches pages like /careers/apply that a fixed list would miss.
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


def extract_emails_from_html(html):
    found = set()
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.select('a[href^="mailto:"]'):
        addr = a["href"][len("mailto:"):].split("?", 1)[0].strip().lower()
        if validate_syntax(addr):
            found.add(addr)

    for match in EMAIL_REGEX.findall(soup.get_text(" ")):
        addr = match.strip().lower()
        if validate_syntax(addr):
            found.add(addr)

    return found, soup


def extract_same_domain_links(soup, base_url, domain):
    links = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.netloc.lower().endswith(domain.lower()) and parsed.scheme in ("http", "https"):
            links.add(full.split("#")[0])
    return links


def scrape_site_for_emails(domain, max_pages=MAX_PAGES_PER_DOMAIN):
    found = {}  # email -> source url
    session = requests.Session()

    for scheme in ("https", "http"):
        base_url = f"{scheme}://{domain}/"
        home_html = fetch_page(session, base_url)
        if home_html is not None:
            break
    else:
        return found  # site unreachable on both schemes

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

        for link in extract_same_domain_links(soup, url, domain):
            if link not in visited:
                queue.append(link)

        time.sleep(CRAWL_DELAY_SECONDS)

    return found


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
# SERPAPI PAGE DISCOVERY (used the way the "clauneck" gem does:
# Google search -> candidate pages -> scrape them for emails)
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


# ============================================================
# MAIN LOOP
# ============================================================

print()
print(f"Hunter.io lookups: {'ENABLED' if USE_HUNTER else 'DISABLED (no HUNTER_API_KEY set -- running free)'}")
print(f"SMTP verification: {'ENABLED' if ENABLE_SMTP_VERIFY else 'DISABLED (guesses will be labeled UNVERIFIED)'}"
      + ("" if ENABLE_SMTP_VERIFY and MAILSCOUT_AVAILABLE else ""))
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

    # --------------------------------------------------------
    # 1. CRAWL THE COMPANY'S OWN SITE (highest confidence, free)
    # --------------------------------------------------------
    print()
    print(f"Crawling company website (up to {MAX_PAGES_PER_DOMAIN} pages)...")
    scraped = scrape_site_for_emails(domain)

    for email, source_url in scraped.items():
        if email in existing_emails:
            continue

        result_domain = email.split("@", 1)[1]
        mx_ok = check_mx(result_domain)

        domain_results.append({
            "domain": domain,
            "email": email,
            "first_name": "", "last_name": "", "position": "", "department": "",
            "type": "generic" if email.split("@")[0] in COMMON_EMAIL_PREFIXES else "personal",
            "confidence": "",
            "source": f"Website ({source_url})",
            "syntax": "VALID",
            "mx": "FOUND" if mx_ok else "NOT_FOUND",
            "catch_all": ca_status if result_domain == domain else "UNKNOWN",
            "status": "FOUND_ON_SITE",
        })
        existing_emails.add(email)

    print(f"Found {len(scraped)} email(s) published on the site.")

    # --------------------------------------------------------
    # 2. HUNTER (optional)
    # --------------------------------------------------------
    if USE_HUNTER:
        print()
        print("Searching Hunter...")

        for item in hunter_search(domain):
            email = item.get("value", "").strip().lower()
            if not email or email in existing_emails:
                continue

            mx_ok = check_mx(email.split("@", 1)[1])

            domain_results.append({
                "domain": domain,
                "email": email,
                "first_name": normalize_field(item.get("first_name")),
                "last_name": normalize_field(item.get("last_name")),
                "position": normalize_field(item.get("position")),
                "department": normalize_field(item.get("department")),
                "type": normalize_field(item.get("type")),
                "confidence": item.get("confidence", ""),
                "source": "Hunter",
                "syntax": "VALID" if validate_syntax(email) else "INVALID",
                "mx": "FOUND" if mx_ok else "NOT_FOUND",
                "catch_all": ca_status,
                "status": "FROM_HUNTER",
            })
            existing_emails.add(email)

    # --------------------------------------------------------
    # 2b. OMKAR CLOUD CONTACT SCRAPER (optional)
    # --------------------------------------------------------
    if USE_OMKAR:
        print()
        print("Searching Omkar Cloud contact scraper...")

        for item in omkar_search(domain):
            email = item.get("value", "").strip().lower()
            if not email or email in existing_emails:
                continue

            mx_ok = check_mx(email.split("@", 1)[1])

            domain_results.append({
                "domain": domain,
                "email": email,
                "first_name": "", "last_name": "", "position": "", "department": "",
                "type": "generic" if email.split("@")[0] in COMMON_EMAIL_PREFIXES else "personal",
                "confidence": "",
                "source": "Omkar Cloud (" + ", ".join(item.get("sources", [])[:1]) + ")"
                           if item.get("sources") else "Omkar Cloud",
                "syntax": "VALID" if validate_syntax(email) else "INVALID",
                "mx": "FOUND" if mx_ok else "NOT_FOUND",
                "catch_all": ca_status,
                "status": "FROM_OMKAR",
            })
            existing_emails.add(email)

    # --------------------------------------------------------
    # 2c. SERPAPI PAGE DISCOVERY (optional) -- find pages the
    # same-domain crawler missed, then scrape them the normal way
    # --------------------------------------------------------
    if USE_SERPAPI:
        print()
        print("Discovering additional pages via SerpApi...")
        discovered_urls = serpapi_discover_pages(domain)
        print(f"Found {len(discovered_urls)} candidate page(s) via search.")

        session = requests.Session()
        for url in discovered_urls:
            parsed = urlparse(url)
            if not parsed.netloc.lower().endswith(domain.lower()):
                continue  # stay on the same company, ignore off-site hits

            html = fetch_page(session, url)
            if not html:
                continue

            emails_here, _ = extract_emails_from_html(html)
            for email in emails_here:
                if email in existing_emails:
                    continue

                result_domain = email.split("@", 1)[1]
                mx_ok = check_mx(result_domain)

                domain_results.append({
                    "domain": domain,
                    "email": email,
                    "first_name": "", "last_name": "", "position": "", "department": "",
                    "type": "generic" if email.split("@")[0] in COMMON_EMAIL_PREFIXES else "personal",
                    "confidence": "",
                    "source": f"SerpApi discovery ({url})",
                    "syntax": "VALID",
                    "mx": "FOUND" if mx_ok else "NOT_FOUND",
                    "catch_all": ca_status if result_domain == domain else "UNKNOWN",
                    "status": "FOUND_VIA_SERPAPI",
                })
                existing_emails.add(email)

            time.sleep(CRAWL_DELAY_SECONDS)

    # --------------------------------------------------------
    # 3. COMMON RECRUITMENT PREFIXES (guesses -- honestly labeled)
    # --------------------------------------------------------
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

            domain_results.append({
                "domain": domain,
                "email": email,
                "first_name": "", "last_name": "", "position": "", "department": "",
                "type": "generic",
                "confidence": "",
                "source": "Common recruitment address (guess)",
                "syntax": "VALID",
                "mx": "FOUND",
                "catch_all": ca_status,
                "status": status,
            })
            existing_emails.add(email)
            recruitment_count += 1

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------
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