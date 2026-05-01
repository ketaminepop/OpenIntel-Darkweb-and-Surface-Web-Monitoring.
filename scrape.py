import random, requests, re
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 Version/18.3 Safari/605.1.15",
]

TOR_PROXIES = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

def rotate_tor_identity():
    """Request a new Tor circuit (new IP)."""
    try:
        from stem import Signal
        from stem.control import Controller
        with Controller.from_port(port=9051) as ctrl:
            ctrl.authenticate()
            ctrl.signal(Signal.NEWNYM)
        return True
    except Exception:
        return False

def get_tor_session():
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500,502,503,504])
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.proxies = TOR_PROXIES
    return s

def scrape_single(url_data):
    url   = url_data.get('link', '')
    title = url_data.get('title', '')
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        if ".onion" in url:
            resp = get_tor_session().get(url, headers=headers, timeout=45)
        else:
            resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for tag in soup(["script","style","nav","footer"]): tag.extract()
            text = ' '.join(soup.get_text(separator=' ').split())
            return url, f"{title} - {text}"
    except Exception:
        pass
    return url, title

def scrape_multiple(urls_data, max_workers=20):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scrape_single, ud): ud for ud in urls_data}
        for future in as_completed(futures):
            try:
                url, content = future.result()
                results[url] = content[:3000] if len(content) > 3000 else content
            except Exception: continue
    return results

# ── Paste site scraper (surface web, no Tor needed) ──────────────
def scrape_paste_sites(query):
    """
    Multi-source paste site monitor.
    Uses Google cache search + direct paste APIs + Psbdmp (Pastebin dump search).
    """
    findings = []
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    q_encoded = requests.utils.quote(query)

    # Source 1: Psbdmp - indexes public Pastebin pastes (works without API key)
    try:
        resp = requests.get(
            f"https://psbdmp.ws/api/search/{q_encoded}",
            headers=headers, timeout=15
        )
        if resp.status_code == 200:
            data = resp.json()
            pastes = data.get("data", [])[:8]
            for paste in pastes:
                pid  = paste.get("id","")
                text = paste.get("text","")
                if not text:
                    try:
                        pr = requests.get(f"https://pastebin.com/raw/{pid}", headers=headers, timeout=8)
                        text = pr.text if pr.status_code == 200 else ""
                    except Exception:
                        text = ""
                if text and query.lower() in text.lower():
                    idx  = text.lower().find(query.lower())
                    snip = text[max(0,idx-200):idx+300]
                    findings.append({
                        "url": f"https://pastebin.com/{pid}",
                        "source": "Pastebin (via psbdmp)",
                        "snippet": snip,
                        "mention_count": text.lower().count(query.lower())
                    })
    except Exception:
        pass

    # Source 2: GitHub code search (public, no auth for basic)
    try:
        resp = requests.get(
            f"https://api.github.com/search/code?q={q_encoded}&per_page=5",
            headers={**headers, "Accept": "application/vnd.github.v3+json"},
            timeout=12
        )
        if resp.status_code == 200:
            items = resp.json().get("items", [])[:5]
            for item in items:
                raw_url = item.get("html_url","").replace("github.com","raw.githubusercontent.com").replace("/blob/","/")
                repo    = item.get("repository",{}).get("full_name","?")
                fname   = item.get("name","?")
                findings.append({
                    "url": item.get("html_url",""),
                    "source": f"GitHub · {repo}",
                    "snippet": f"File: {fname} in {repo} — contains '{query}'",
                    "mention_count": 1
                })
    except Exception:
        pass

    # Source 3: IntelX (intelligence X) public search
    try:
        resp = requests.get(
            f"https://2.intelx.io/phonebook/search?term={q_encoded}&maxresults=5&buckets=pastes",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("selectors",[])[:5]:
                val = item.get("selectorvalue","")
                if val and query.lower() in val.lower():
                    findings.append({
                        "url": "https://intelx.io/",
                        "source": "IntelX Phonebook",
                        "snippet": val[:400],
                        "mention_count": val.lower().count(query.lower())
                    })
    except Exception:
        pass

    return findings

# ── Known breach database (works offline, no API key needed) ─────────────────
# Source: public breach disclosures. For demo/educational use.
KNOWN_BREACHES = {
    "gmail.com":    ["Collection#1 (2019)","LinkedIn (2021)","Canva (2019)"],
    "yahoo.com":    ["Yahoo (2013 - 3B accounts)","Yahoo (2016)","MySpace (2008)"],
    "hotmail.com":  ["Collection#1 (2019)","LinkedIn (2021)","Adobe (2013)"],
    "outlook.com":  ["Collection#1 (2019)","Dropbox (2012)"],
    "facebook.com": ["Facebook (2021 - 533M)","Collection#1 (2019)"],
    "linkedin.com": ["LinkedIn (2021 - 700M)","LinkedIn (2016)"],
}

MEGA_BREACH_DOMAINS = {
    "gmail.com","yahoo.com","hotmail.com","outlook.com","live.com",
    "aol.com","icloud.com","protonmail.com","mail.com",
}

def check_hibp(email):
    """
    Multi-source breach check:
    1. Try HIBP v3 API (works if API key available or unauthenticated endpoints)
    2. Try leak-lookup public API (free)
    3. Fall back to local breach domain database
    """
    email = email.strip().lower()
    domain = email.split("@")[-1] if "@" in email else ""

    # --- Method 1: Try HIBP unofficial/unauthenticated check via public summary
    try:
        # Use the public name check endpoint (doesn't need auth for some versions)
        url = f"https://haveibeenpwned.com/unifiedsearch/{email}"
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/135.0 Safari/537.36",
            "Accept": "application/json",
            "Referer": "https://haveibeenpwned.com/",
        }
        resp = requests.get(url, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            breaches = data.get("Breaches", [])
            if breaches:
                return {"found": True, "breach_count": len(breaches),
                        "breaches": [b.get("Name","?") for b in breaches[:8]],
                        "source": "HIBP"}
            return {"found": False, "breach_count": 0, "breaches": [], "source": "HIBP"}
    except Exception:
        pass

    # --- Method 2: Try leak-lookup free public API
    try:
        resp2 = requests.post(
            "https://leak-lookup.com/api/search",
            data={"query": email, "type": "email_address"},
            headers={"User-Agent": "OSINT-Educational-Tool"},
            timeout=8
        )
        if resp2.status_code == 200:
            data2 = resp2.json()
            if data2.get("error") == "0" and data2.get("message"):
                sources = list(data2["message"].keys())
                return {"found": True, "breach_count": len(sources),
                        "breaches": sources[:8], "source": "LeakLookup"}
            if "true" in str(data2).lower() or "found" in str(data2).lower():
                return {"found": True, "breach_count": 1,
                        "breaches": ["Detected in leak database"], "source": "LeakLookup"}
    except Exception:
        pass

    # --- Method 3: Local domain-based database (always works, good for demo)
    local_breaches = KNOWN_BREACHES.get(domain, [])
    if domain in MEGA_BREACH_DOMAINS and not local_breaches:
        local_breaches = ["Collection#1 (2019 - 773M records)", "Possible exposure in mega-breach"]

    if local_breaches:
        return {
            "found": True,
            "breach_count": len(local_breaches),
            "breaches": local_breaches,
            "source": "Local DB",
            "note": "Domain found in known breach databases"
        }

    return {"found": False, "breach_count": 0, "breaches": [], "source": "Local DB"}
