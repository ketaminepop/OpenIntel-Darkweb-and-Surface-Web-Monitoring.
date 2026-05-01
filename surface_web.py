"""
surface_web.py — Surface Web Intelligence Engine for OPEN INTEL
==============================================================
Modules:
  1. WHOIS Lookup          (RDAP + fallback)
  2. DNS Reconnaissance    (Google DoH + Cloudflare DoH)
  3. Subdomain Enumeration (crt.sh + HackerTarget + RapidDNS + CommonCrawl)
  4. IP Intelligence       (ip-api + Shodan InternetDB + GreyNoise Community)
  5. Username Hunt         (50+ platforms, concurrent)
  6. Google Dorking        (DuckDuckGo HTML scrape — no API key)
  7. Wayback Machine       (CDX API)
  8. Email OSINT           (format, MX, Gravatar, Hunter, breach hints)
  9. Phone Intelligence    (pattern + country code + OSINT dorks)
 10. Certificate Transparency (crt.sh)
 11. Technology Fingerprinting (headers + HTML patterns)
 12. Threat Intelligence  (OTX + URLhaus + MalwareBazaar + ThreatFox)

All sources are publicly available — no paid API keys required.
"""

import hashlib
import json
import random
import re
import socket
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote, urlparse

import requests
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore")

# ── Shared helpers ────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
]


def _hdrs(extra=None):
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if extra:
        h.update(extra)
    return h


def _clean_domain(raw):
    raw = raw.strip().lower()
    if raw.startswith(("http://", "https://")):
        raw = urlparse(raw).netloc
    return raw.split("/")[0].split("?")[0]


# ══════════════════════════════════════════════════════════════════════════════
# 1. WHOIS LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def whois_lookup(target: str) -> dict:
    """
    Multi-source WHOIS/RDAP lookup.
    Sources: RDAP.org → whoisjson.com → raw text fallback
    """
    domain = _clean_domain(target)
    result = {"target": domain, "raw": "", "parsed": {}, "source": ""}

    # ── Source 1: RDAP.org (modern, JSON, no auth) ────────────────────────────
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers=_hdrs(), timeout=12
        )
        if resp.status_code == 200:
            data = resp.json()
            events = {
                e.get("eventAction", ""): e.get("eventDate", "")
                for e in data.get("events", [])
            }
            registrar, registrant = "", {}
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                vcard = ent.get("vcardArray", [None, []])[1]
                for v in vcard:
                    if "registrar" in roles and v[0] == "fn":
                        registrar = v[3]
                    if "registrant" in roles:
                        if v[0] == "fn":
                            registrant["name"] = v[3]
                        if v[0] == "email":
                            registrant["email"] = v[3]
            ns = [n.get("ldhName", "") for n in data.get("nameservers", [])]
            result["parsed"] = {
                "domain":      domain,
                "registrar":   registrar,
                "registrant":  registrant,
                "created":     events.get("registration", "?"),
                "expires":     events.get("expiration", "?"),
                "updated":     events.get("last changed", "?"),
                "nameservers": ns,
                "status":      data.get("status", []),
                "dnssec":      data.get("secureDNS", {}).get("delegationSigned", False),
            }
            result["source"] = "RDAP"
            result["raw"] = json.dumps(data, indent=2)[:4000]
            return result
    except Exception:
        pass

    # ── Source 2: whoisjson.com ───────────────────────────────────────────────
    try:
        resp = requests.get(
            f"https://whoisjson.com/api/v1/whois?domain={domain}",
            headers=_hdrs(), timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            result["parsed"] = {
                "domain":      domain,
                "registrar":   data.get("registrar", {}).get("name", "?"),
                "created":     data.get("creation_date", "?"),
                "expires":     data.get("expiration_date", "?"),
                "nameservers": data.get("name_servers", []),
                "status":      data.get("status", []),
            }
            result["source"] = "WhoisJSON"
            result["raw"] = json.dumps(data, indent=2)[:4000]
            return result
    except Exception:
        pass

    # ── Source 3: whois.arin.net (IP WHOIS fallback) ──────────────────────────
    try:
        resp = requests.get(
            f"https://rdap.arin.net/registry/domain/{domain}",
            headers=_hdrs(), timeout=10
        )
        if resp.status_code == 200:
            result["parsed"] = {"domain": domain, "note": "ARIN RDAP fallback"}
            result["source"] = "ARIN RDAP"
            result["raw"] = resp.text[:2000]
            return result
    except Exception:
        pass

    result["error"] = "All WHOIS sources unavailable"
    return result


# ══════════════════════════════════════════════════════════════════════════════
# 2. DNS RECONNAISSANCE
# ══════════════════════════════════════════════════════════════════════════════

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR"]


def dns_recon(domain: str) -> dict:
    """
    Full DNS enumeration via Google DoH + Cloudflare DoH (both free, no auth).
    Returns all record types in parallel.
    """
    domain = _clean_domain(domain)
    records = {}

    def _query(rtype):
        # Google DNS-over-HTTPS
        try:
            r = requests.get(
                f"https://dns.google/resolve?name={domain}&type={rtype}",
                headers=_hdrs(), timeout=8
            )
            if r.status_code == 200:
                answers = r.json().get("Answer", r.json().get("Authority", []))
                vals = [a.get("data", "") for a in answers if a.get("data")]
                if vals:
                    return rtype, vals
        except Exception:
            pass
        # Cloudflare fallback
        try:
            r = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}",
                headers={**_hdrs(), "Accept": "application/dns-json"},
                timeout=8
            )
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                vals = [a.get("data", "") for a in answers if a.get("data")]
                if vals:
                    return rtype, vals
        except Exception:
            pass
        return rtype, []

    with ThreadPoolExecutor(max_workers=10) as ex:
        for rtype, vals in ex.map(lambda rt: _query(rt), DNS_RECORD_TYPES):
            if vals:
                records[rtype] = vals

    # Socket sanity check
    try:
        records.setdefault("A", [socket.gethostbyname(domain)])
    except Exception:
        pass

    # SPF / DMARC / DKIM extraction from TXT
    spf, dmarc = [], []
    for txt in records.get("TXT", []):
        if "v=spf1" in txt.lower():
            spf.append(txt)
        if "v=dmarc1" in txt.lower():
            dmarc.append(txt)

    return {
        "domain":    domain,
        "records":   records,
        "spf":       spf,
        "dmarc":     dmarc,
        "timestamp": datetime.now().isoformat(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

# ── Known country-code second-level domains (ccSLDs) ─────────────────────────
# Without this, charusat.ac.in → root = "ac.in" → fetches ALL .ac.in subdomains
# With this,    charusat.ac.in → root = "charusat.ac.in" → correct
_CC_SLDS = {
    "ac.in","co.in","gov.in","org.in","net.in","edu.in","res.in","mil.in","nic.in",
    "ac.uk","co.uk","gov.uk","org.uk","me.uk","net.uk","ltd.uk","plc.uk","sch.uk",
    "com.au","net.au","org.au","edu.au","gov.au","ac.au",
    "co.nz","net.nz","org.nz","gov.nz","ac.nz","school.nz",
    "com.br","net.br","org.br","gov.br","edu.br",
    "co.jp","ne.jp","or.jp","go.jp","ac.jp","ad.jp","ed.jp",
    "com.cn","net.cn","org.cn","gov.cn","edu.cn","ac.cn",
    "com.pk","net.pk","org.pk","gov.pk","edu.pk","ac.pk",
    "co.za","net.za","org.za","gov.za","ac.za","edu.za",
    "com.sg","edu.sg","gov.sg","net.sg","org.sg",
    "com.my","net.my","org.my","gov.my","edu.my",
    "com.hk","net.hk","org.hk","gov.hk","edu.hk",
    "com.ae","net.ae","org.ae","gov.ae","ac.ae",
    "com.sa","net.sa","org.sa","gov.sa","edu.sa",
    "com.mx","net.mx","org.mx","gob.mx","edu.mx",
    "com.ar","net.ar","org.ar","gov.ar","edu.ar",
}

def _root_domain(domain: str) -> str:
    """
    Return the registrable root domain, correctly handling ccSLDs.
    charusat.ac.in  -> charusat.ac.in  (NOT ac.in)
    sub.google.co.uk -> google.co.uk   (NOT co.uk)
    sub.example.com  -> example.com
    """
    parts = domain.split(".")
    if len(parts) >= 3:
        ccsld = ".".join(parts[-2:])
        if ccsld in _CC_SLDS:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) > 1 else domain


def subdomain_enum(domain: str) -> dict:
    """
    Passive subdomain enumeration.
    Sources: crt.sh · HackerTarget · RapidDNS · CommonCrawl index
    Then live-checks each via socket resolution (concurrent).
    """
    domain = _clean_domain(domain)
    root = _root_domain(domain)   # FIXED: was parts[-2:] — broken for .ac.in .co.uk etc.
    found = set()

    # ── crt.sh ───────────────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{root}&output=json",
            headers=_hdrs(), timeout=25
        )
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{root}") or name == root:
                        found.add(name)
    except Exception:
        pass

    # ── HackerTarget ─────────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={root}",
            headers=_hdrs(), timeout=15
        )
        if r.status_code == 200 and "error" not in r.text[:30].lower():
            for line in r.text.strip().split("\n"):
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{root}") or sub == root:
                    found.add(sub)
    except Exception:
        pass

    # ── RapidDNS ─────────────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{root}?full=1",
            headers={**_hdrs(), "Accept": "text/html"},
            timeout=15
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "lxml")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True).lower()
                if text.endswith(f".{root}"):
                    found.add(text)
    except Exception:
        pass

    # ── CommonCrawl index ────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"http://index.commoncrawl.org/CC-MAIN-2024-10-index"
            f"?url=*.{root}&output=json&limit=100",
            headers=_hdrs(), timeout=15
        )
        if r.status_code == 200:
            for line in r.text.strip().split("\n")[:100]:
                try:
                    obj = json.loads(line)
                    host = urlparse(obj.get("url", "")).netloc.lower().split(":")[0]
                    if host.endswith(f".{root}"):
                        found.add(host)
                except Exception:
                    pass
    except Exception:
        pass

    # ── Live resolution ───────────────────────────────────────────────────────
    def _resolve(sub):
        try:
            return sub, socket.gethostbyname(sub)
        except Exception:
            return sub, None

    subs_list = list(found)[:150]
    live_results = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        for sub, ip in ex.map(_resolve, subs_list):
            live_results.append({"subdomain": sub, "ip": ip, "live": ip is not None})

    live_results.sort(key=lambda x: (not x["live"], x["subdomain"]))

    return {
        "domain":      root,
        "total_found": len(found),
        "live_count":  sum(1 for s in live_results if s["live"]),
        "subdomains":  live_results[:100],
    }


# ══════════════════════════════════════════════════════════════════════════════
# 4. IP INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

def ip_intelligence(target: str) -> dict:
    """
    IP/domain deep-dive: geolocation, ASN, open ports, vuln tags, reputation.
    Sources: ip-api.com · Shodan InternetDB (free!) · GreyNoise Community · ipinfo.io
    """
    target = target.strip()
    ip = target
    resolved_from = None

    # Resolve domain → IP
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        try:
            ip = socket.gethostbyname(target)
            resolved_from = target
        except Exception:
            pass

    result = {"target": target, "ip": ip, "resolved_from": resolved_from}

    # ── ip-api.com (free, 45 req/min, very detailed) ──────────────────────────
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=66846719",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                result["geo"] = {
                    "country":      d.get("country"),
                    "country_code": d.get("countryCode"),
                    "region":       d.get("regionName"),
                    "city":         d.get("city"),
                    "zip":          d.get("zip"),
                    "lat":          d.get("lat"),
                    "lon":          d.get("lon"),
                    "timezone":     d.get("timezone"),
                    "isp":          d.get("isp"),
                    "org":          d.get("org"),
                    "asn":          d.get("as"),
                    "mobile":       d.get("mobile"),
                    "proxy":        d.get("proxy"),
                    "hosting":      d.get("hosting"),
                }
    except Exception:
        pass

    # ── Shodan InternetDB (free, no API key needed!) ──────────────────────────
    try:
        r = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            result["shodan"] = {
                "open_ports": d.get("ports", []),
                "hostnames":  d.get("hostnames", []),
                "cpes":       d.get("cpes", []),
                "tags":       d.get("tags", []),
                "vulns":      d.get("vulns", []),
            }
    except Exception:
        pass

    # ── GreyNoise Community (free endpoint, no key for community check) ────────
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            result["greynoise"] = {
                "noise":          d.get("noise"),
                "riot":           d.get("riot"),
                "classification": d.get("classification"),
                "name":           d.get("name"),
                "message":        d.get("message"),
            }
    except Exception:
        pass

    # ── ipinfo.io (free tier, no key required for basic) ─────────────────────
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            result.setdefault("geo", {})
            result["geo"]["hostname"] = d.get("hostname", "")
            result["geo"]["org_raw"]  = d.get("org", "")
    except Exception:
        pass

    # ── Reverse DNS ───────────────────────────────────────────────────────────
    try:
        result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # ── Risk assessment ───────────────────────────────────────────────────────
    risk_flags = []
    if result.get("greynoise", {}).get("noise"):
        risk_flags.append("Scanning/Noise source (GreyNoise)")
    if result.get("shodan", {}).get("vulns"):
        risk_flags.append(f"CVEs detected: {', '.join(result['shodan']['vulns'][:3])}")
    if result.get("geo", {}).get("proxy"):
        risk_flags.append("Proxy/VPN/Tor exit node detected")
    if result.get("geo", {}).get("hosting"):
        risk_flags.append("Hosting/datacenter IP")
    result["risk_flags"] = risk_flags

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 5. USERNAME HUNT
# ══════════════════════════════════════════════════════════════════════════════

PLATFORMS = {
    "GitHub":        "https://github.com/{u}",
    "GitLab":        "https://gitlab.com/{u}",
    "Twitter/X":     "https://twitter.com/{u}",
    "Instagram":     "https://www.instagram.com/{u}/",
    "TikTok":        "https://www.tiktok.com/@{u}",
    "Reddit":        "https://www.reddit.com/user/{u}/",
    "YouTube":       "https://www.youtube.com/@{u}",
    "Pinterest":     "https://www.pinterest.com/{u}/",
    "Tumblr":        "https://{u}.tumblr.com/",
    "Medium":        "https://medium.com/@{u}",
    "Dev.to":        "https://dev.to/{u}",
    "HackerNews":    "https://news.ycombinator.com/user?id={u}",
    "Keybase":       "https://keybase.io/{u}",
    "Telegram":      "https://t.me/{u}",
    "Twitch":        "https://www.twitch.tv/{u}",
    "Steam":         "https://steamcommunity.com/id/{u}",
    "Pastebin":      "https://pastebin.com/u/{u}",
    "Replit":        "https://replit.com/@{u}",
    "Mastodon":      "https://mastodon.social/@{u}",
    "Flickr":        "https://www.flickr.com/people/{u}/",
    "Vimeo":         "https://vimeo.com/{u}",
    "SoundCloud":    "https://soundcloud.com/{u}",
    "Behance":       "https://www.behance.net/{u}",
    "Dribbble":      "https://dribbble.com/{u}",
    "ProductHunt":   "https://www.producthunt.com/@{u}",
    "HuggingFace":   "https://huggingface.co/{u}",
    "DockerHub":     "https://hub.docker.com/u/{u}/",
    "npmjs":         "https://www.npmjs.com/~{u}",
    "PyPI":          "https://pypi.org/user/{u}/",
    "StackOverflow": "https://stackoverflow.com/users/{u}",
    "Kaggle":        "https://www.kaggle.com/{u}",
    "CodePen":       "https://codepen.io/{u}",
    "Bitbucket":     "https://bitbucket.org/{u}/",
    "About.me":      "https://about.me/{u}",
    "Gravatar":      "https://gravatar.com/{u}",
    "VK":            "https://vk.com/{u}",
    "Quora":         "https://www.quora.com/profile/{u}",
    "Fiverr":        "https://www.fiverr.com/{u}",
    "HackerOne":     "https://hackerone.com/{u}",
    "BugCrowd":      "https://bugcrowd.com/{u}",
    "Exploit-DB":    "https://www.exploit-db.com/author/{u}",
    "Shodan":        "https://www.shodan.io/search?query={u}",
    "Snapchat":      "https://www.snapchat.com/add/{u}",
    "Spotify":       "https://open.spotify.com/user/{u}",
    "Tryhackme":     "https://tryhackme.com/p/{u}",
    "HackTheBox":    "https://app.hackthebox.com/users/{u}",
    "Leetcode":      "https://leetcode.com/{u}/",
    "Codeforces":    "https://codeforces.com/profile/{u}",
    "Codewars":      "https://www.codewars.com/users/{u}",
    "GeeksForGeeks": "https://auth.geeksforgeeks.org/user/{u}/",
    "Linktree":      "https://linktr.ee/{u}",
}

NOT_FOUND_STRINGS = [
    "page not found", "user not found", "this account doesn't exist",
    "sorry, this page isn't available", "doesn't exist", "no user found",
    "profile not found", "account suspended", "this profile doesn't exist",
    "page doesn't exist", "not found", "404", "no results found",
    "this username is not available", "this page could not be found",
    "the page you're looking for doesn't exist",
]


def username_hunt(username: str) -> dict:
    """Check username existence across 50+ platforms concurrently."""
    username = username.strip()

    def _check(platform, url_template):
        url = url_template.replace("{u}", username)
        try:
            r = requests.get(
                url,
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=12,
                allow_redirects=True
            )
            if r.status_code == 200:
                content = r.text.lower()
                if any(ind in content for ind in NOT_FOUND_STRINGS):
                    return platform, url, "not_found", 200
                return platform, url, "found", 200
            if r.status_code == 404:
                return platform, url, "not_found", 404
            return platform, url, "other", r.status_code
        except Exception as e:
            return platform, url, "error", str(e)

    found, not_found = [], []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_check, p, u): p for p, u in PLATFORMS.items()}
        for future in as_completed(futures):
            try:
                platform, url, status, code = future.result()
                if status == "found":
                    found.append({"platform": platform, "url": url})
                elif status == "not_found":
                    not_found.append({"platform": platform, "url": url})
            except Exception:
                pass

    found.sort(key=lambda x: x["platform"])

    return {
        "username":    username,
        "found_count": len(found),
        "checked":     len(PLATFORMS),
        "found":       found,
        "not_found":   not_found,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6. GOOGLE DORKING (via DuckDuckGo HTML — no API key, no CAPTCHA wall)
# ══════════════════════════════════════════════════════════════════════════════

DORK_TEMPLATES = {
    "Exposed Files": [
        'site:{t} filetype:pdf OR filetype:xlsx OR filetype:docx',
        'site:{t} filetype:sql OR filetype:db OR filetype:bak',
        'site:{t} filetype:env OR filetype:xml OR filetype:json',
        'site:{t} ext:log "password" OR "credential" OR "secret"',
        'site:{t} ext:config OR ext:cfg OR ext:ini',
        'site:{t} "index of /" intitle:"index of"',
    ],
    "Login Panels": [
        'site:{t} inurl:admin OR inurl:login OR inurl:dashboard',
        'site:{t} intitle:"login" OR intitle:"admin panel" OR intitle:"sign in"',
        'site:{t} inurl:wp-admin OR inurl:phpmyadmin OR inurl:adminer',
        'site:{t} inurl:cpanel OR inurl:webmail OR inurl:vpn OR inurl:portal',
        'site:{t} inurl:jenkins OR inurl:gitlab OR inurl:kibana',
    ],
    "Sensitive Data": [
        'site:{t} "api_key" OR "api_secret" OR "access_token" OR "client_secret"',
        'site:{t} "password" OR "passwd" filetype:txt OR filetype:env',
        'site:{t} "BEGIN RSA PRIVATE KEY" OR "BEGIN OPENSSH PRIVATE KEY"',
        'site:{t} "DB_PASSWORD" OR "DATABASE_URL" OR "SMTP_PASSWORD"',
        '"@{t}" email list OR dump OR leaked OR pastebin',
        'site:{t} "aws_access_key" OR "aws_secret" OR "s3_bucket"',
    ],
    "Subdomains & Dev": [
        'site:*.{t} -www',
        'site:{t} -www inurl:dev OR inurl:staging OR inurl:test OR inurl:uat',
        'site:{t} inurl:api OR inurl:beta OR inurl:sandbox',
        'site:{t} intitle:"phpinfo()" OR "PHP Version"',
        'site:{t} "robots.txt" disallow',
    ],
    "CVE / Exploits": [
        '"{t}" CVE OR vulnerability OR 0day OR exploit',
        '"{t}" "security advisory" OR "patch" OR "breach" OR "disclosure"',
        '"{t}" "data breach" OR "leaked" OR "exposed" OR "compromised"',
        '"{t}" ransomware OR malware OR "remote code execution"',
    ],
    "People / Social": [
        '"{t}" site:linkedin.com OR site:twitter.com OR site:github.com',
        '"{t}" site:pastebin.com OR site:ghostbin.co',
        '"{t}" "resume" OR "CV" filetype:pdf',
        '"{t}" site:glassdoor.com OR site:crunchbase.com',
    ],
    "Infrastructure": [
        'site:{t} intitle:"Apache" OR intitle:"nginx" OR intitle:"IIS"',
        'site:{t} intitle:"Welcome to" OR intitle:"Default Page"',
        'site:{t} "Traceback" OR "stack trace" OR "Exception" filetype:log',
        'ip:{t}',
    ],
    "Historical": [
        'cache:{t}',
        'site:web.archive.org/{t}',
        'site:archive.org "{t}"',
        '"{t}" site:reddit.com',
    ],
}


def generate_dorks(target: str) -> dict:
    """Build all dork categories for a target domain/person/company."""
    t = _clean_domain(target) if "/" not in target and "@" not in target else target.strip()
    return {
        "target": t,
        "dorks":  {cat: [d.replace("{t}", t) for d in dlist]
                   for cat, dlist in DORK_TEMPLATES.items()},
    }


def search_dork(query: str, num: int = 10) -> list:
    """
    Execute a dork search via DuckDuckGo HTML endpoint.
    No API key required; respectful of rate limits via random delay.
    """
    results = []
    try:
        time.sleep(random.uniform(0.5, 1.2))   # polite delay
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://duckduckgo.com/",
            },
            timeout=15
        )
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "lxml")
            for r in soup.select(".result"):
                title_el  = r.select_one(".result__title")
                snip_el   = r.select_one(".result__snippet")
                a_el      = r.select_one("a.result__a")
                if title_el and a_el:
                    results.append({
                        "title":   title_el.get_text(strip=True),
                        "url":     a_el.get("href", ""),
                        "snippet": snip_el.get_text(strip=True) if snip_el else "",
                    })
                if len(results) >= num:
                    break
    except Exception:
        pass
    return results[:num]


# ══════════════════════════════════════════════════════════════════════════════
# 7. WAYBACK MACHINE
# ══════════════════════════════════════════════════════════════════════════════

def wayback_lookup(domain: str) -> dict:
    """
    Retrieve historical snapshots from the Wayback Machine CDX API.
    Returns year-by-year snapshot counts + 50 most recent snapshots.
    """
    domain = _clean_domain(domain)
    result = {"domain": domain, "snapshots": [], "summary": {}}

    # Availability check
    try:
        r = requests.get(
            f"https://archive.org/wayback/available?url={domain}",
            headers=_hdrs(), timeout=10
        )
        if r.status_code == 200:
            closest = r.json().get("archived_snapshots", {}).get("closest", {})
            if closest:
                result["closest"] = {
                    "url":       closest.get("url"),
                    "timestamp": closest.get("timestamp"),
                    "status":    closest.get("status"),
                }
    except Exception:
        pass

    # CDX snapshot list
    try:
        r = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": domain,
                "output": "json",
                "fl": "timestamp,statuscode,mimetype,original",
                "limit": 300,
                "collapse": "timestamp:6",
            },
            headers=_hdrs(), timeout=25
        )
        if r.status_code == 200:
            data = r.json()
            if len(data) > 1:
                snapshots = []
                for row in data[1:]:
                    ts = row[0]
                    try:
                        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                        fmt = dt.strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        fmt = ts
                    snapshots.append({
                        "timestamp":   ts,
                        "formatted":   fmt,
                        "year":        ts[:4],
                        "status":      row[1],
                        "mime":        row[2],
                        "original":    row[3] if len(row) > 3 else domain,
                        "wayback_url": f"https://web.archive.org/web/{ts}/{domain}",
                    })

                years = {}
                for s in snapshots:
                    years[s["year"]] = years.get(s["year"], 0) + 1

                result["total_snapshots"] = len(snapshots)
                result["snapshots"] = snapshots[:50]
                result["summary"] = {
                    "by_year":    dict(sorted(years.items())),
                    "first_seen": snapshots[-1]["formatted"] if snapshots else None,
                    "last_seen":  snapshots[0]["formatted"] if snapshots else None,
                    "year_range": f"{min(years)} – {max(years)}" if years else "N/A",
                }
    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 8. EMAIL OSINT
# ══════════════════════════════════════════════════════════════════════════════

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "10minutemail.com", "yopmail.com", "trashmail.com", "fakeinbox.com",
    "sharklasers.com", "spam4.me", "trashmail.me", "dispostable.com",
    "spamgourmet.com", "maildrop.cc", "getnada.com", "mailnull.com",
    "spamspot.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "tempr.email", "throwam.com", "discard.email", "mailtemp.net",
}


def email_osint(email: str) -> dict:
    """
    Email intelligence: format validation, disposable check, MX records,
    Gravatar profile lookup, breach hint, search dorks, Hunter format check.
    """
    email = email.strip().lower()
    result = {"email": email, "valid_format": False}

    EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    result["valid_format"] = bool(EMAIL_RE.match(email))
    if not result["valid_format"]:
        result["error"] = "Invalid email format"
        return result

    local, domain = email.split("@", 1)
    result.update({"local": local, "domain": domain})

    # Disposable check
    result["is_disposable"] = domain in DISPOSABLE_DOMAINS

    # MX records
    try:
        r = requests.get(
            f"https://dns.google/resolve?name={domain}&type=MX",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            mxs = [a.get("data", "") for a in r.json().get("Answer", [])]
            result["mx_records"] = mxs
            result["can_receive_email"] = len(mxs) > 0
    except Exception:
        pass

    # Domain age hint from WHOIS
    try:
        w = whois_lookup(domain)
        result["domain_info"] = {
            "registrar": w.get("parsed", {}).get("registrar", "?"),
            "created":   w.get("parsed", {}).get("created", "?"),
        }
    except Exception:
        pass

    # Gravatar (MD5 hash of email)
    email_md5 = hashlib.md5(email.encode()).hexdigest()
    gravatar_profile_url = f"https://www.gravatar.com/{email_md5}.json"
    try:
        r = requests.get(gravatar_profile_url, headers=_hdrs(), timeout=8)
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            result["gravatar"] = {
                "found":        True,
                "display_name": entry.get("displayName", ""),
                "username":     entry.get("preferredUsername", ""),
                "profile_url":  entry.get("profileUrl", ""),
                "about":        entry.get("aboutMe", "")[:200],
                "urls":         [u.get("value", "") for u in entry.get("urls", [])],
                "avatar":       f"https://www.gravatar.com/avatar/{email_md5}?s=200&d=404",
            }
        else:
            result["gravatar"] = {
                "found":  False,
                "avatar": f"https://www.gravatar.com/avatar/{email_md5}?s=200&d=identicon",
            }
    except Exception:
        pass

    # OSINT dorks
    result["osint_dorks"] = [
        f'"{email}"',
        f'"{email}" site:pastebin.com',
        f'"{email}" site:github.com',
        f'"{email}" site:linkedin.com',
        f'"{email}" leaked OR breach OR dump OR combolist',
        f'"{local}" site:twitter.com OR site:reddit.com',
        f'"{local}" "@{domain}"',
    ]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 9. PHONE INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════════

COUNTRY_CODES = {
    "+1": "USA / Canada",  "+44": "United Kingdom", "+91": "India",
    "+86": "China",        "+49": "Germany",         "+33": "France",
    "+81": "Japan",        "+82": "South Korea",     "+39": "Italy",
    "+34": "Spain",        "+7":  "Russia",           "+55": "Brazil",
    "+61": "Australia",    "+52": "Mexico",           "+20": "Egypt",
    "+27": "South Africa", "+971": "UAE",             "+966": "Saudi Arabia",
    "+92": "Pakistan",     "+880": "Bangladesh",      "+234": "Nigeria",
    "+254": "Kenya",       "+90": "Turkey",           "+380": "Ukraine",
    "+48": "Poland",       "+31": "Netherlands",      "+46": "Sweden",
    "+47": "Norway",       "+45": "Denmark",          "+358": "Finland",
    "+41": "Switzerland",  "+43": "Austria",          "+32": "Belgium",
    "+351": "Portugal",    "+30": "Greece",           "+40": "Romania",
    "+420": "Czech Rep.",  "+36": "Hungary",          "+66": "Thailand",
    "+62": "Indonesia",    "+63": "Philippines",      "+84": "Vietnam",
    "+60": "Malaysia",     "+65": "Singapore",        "+94": "Sri Lanka",
    "+977": "Nepal",       "+98": "Iran",             "+93": "Afghanistan",
}


def phone_intel(phone: str) -> dict:
    """
    Phone number intelligence: E.164 normalization, country/carrier hints,
    OSINT dork suggestions, and public lookup links.
    """
    phone = re.sub(r"[^\d+]", "", phone.strip())
    result = {"original": phone}

    if not phone.startswith("+"):
        phone = ("+1" + phone) if len(phone) == 10 else ("+" + phone)
    result["normalized"] = phone

    # Country identification
    for code in sorted(COUNTRY_CODES, key=len, reverse=True):
        if phone.startswith(code):
            result["country_code"] = code
            result["country"]      = COUNTRY_CODES[code]
            result["local_number"] = phone[len(code):]
            break

    local = result.get("local_number", phone.lstrip("+"))

    # OSINT lookups (free public APIs)
    try:
        r = requests.get(
            f"https://api.truecallerapi.com/search?phone={quote(phone)}",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            result["truecaller_hint"] = r.json()
    except Exception:
        pass

    result["osint_links"] = [
        f"https://www.truecaller.com/search/{phone.lstrip('+')}",
        f"https://www.whitepages.com/phone/{phone}",
        f"https://calleridtest.com/",
    ]

    result["osint_dorks"] = [
        f'"{phone}"',
        f'"{local}"',
        f'"{phone}" site:truecaller.com',
        f'"{phone}" site:whitepages.com OR site:411.com',
        f'"{phone}" site:linkedin.com OR site:facebook.com',
        f'"{phone}" "contact" OR "whois" OR "registration"',
    ]

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 10. CERTIFICATE TRANSPARENCY
# ══════════════════════════════════════════════════════════════════════════════

def cert_transparency(domain: str) -> dict:
    """Search crt.sh CT logs for all certificates issued to a domain."""
    domain = _clean_domain(domain)
    certs = []
    seen = set()

    try:
        r = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            headers=_hdrs(), timeout=25
        )
        if r.status_code == 200:
            for c in r.json():
                cid = c.get("id")
                if cid in seen:
                    continue
                seen.add(cid)
                names = [n.strip() for n in c.get("name_value", "").split("\n") if n.strip()]
                certs.append({
                    "id":         cid,
                    "issuer":     c.get("issuer_name", "")[:80],
                    "domains":    names,
                    "not_before": c.get("not_before", ""),
                    "not_after":  c.get("not_after", ""),
                    "logged_at":  c.get("entry_timestamp", ""),
                    "crt_url":    f"https://crt.sh/?id={cid}",
                })
    except Exception:
        pass

    # Extract unique issuers + wildcard count
    issuers = {}
    wildcard_count = 0
    for c in certs:
        iss = c["issuer"].split("O=")[-1].split(",")[0].strip()
        issuers[iss] = issuers.get(iss, 0) + 1
        if any("*" in d for d in c["domains"]):
            wildcard_count += 1

    return {
        "domain":          domain,
        "total_certs":     len(certs),
        "wildcard_certs":  wildcard_count,
        "top_issuers":     dict(sorted(issuers.items(), key=lambda x: -x[1])[:5]),
        "certificates":    certs[:60],
    }


# ══════════════════════════════════════════════════════════════════════════════
# 11. TECHNOLOGY FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════════

CMS_PATTERNS = {
    "WordPress":   ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"],
    "Drupal":      ["drupal.org", "drupal.js", "drupal-settings"],
    "Joomla":      ["/administrator/", "/components/com_"],
    "Magento":     ["mage/", "varien/", "magento"],
    "Shopify":     ["shopify.com", "myshopify", "Shopify.theme"],
    "Wix":         ["wix.com", "_wixApps", "wixStatic"],
    "Squarespace": ["squarespace.com", "squarespace-cdn"],
    "Ghost":       ["ghost.org", "/content/themes/"],
    "PrestaShop":  ["prestashop", "/modules/blocktopmenu/"],
}
JS_PATTERNS = {
    "React":    ["react.js", "react.min.js", "data-reactroot", "__REACT"],
    "Angular":  ["angular.js", "ng-version"],
    "Vue.js":   ["vue.js", "vue.min.js", "__vue__"],
    "Next.js":  ["_next/", "__NEXT_DATA__"],
    "Nuxt.js":  ["nuxt.js", "__NUXT__"],
    "jQuery":   ["jquery.js", "jquery.min.js"],
    "Bootstrap":["bootstrap.css", "bootstrap.min.css"],
    "Tailwind": ["tailwind"],
}
ANALYTICS_PATTERNS = {
    "Google Analytics":   ["google-analytics.com", "gtag("],
    "Google Tag Manager": ["googletagmanager.com", "GTM-"],
    "Hotjar":             ["hotjar.com", "hjid"],
    "Facebook Pixel":     ["connect.facebook.net", "fbq("],
    "HubSpot":            ["hubspot.com", "hs-scripts.com"],
    "Mixpanel":           ["mixpanel.com"],
}
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def tech_fingerprint(url: str) -> dict:
    """
    Full technology stack detection from HTTP headers + HTML content analysis.
    Also grades security header implementation (A–F).
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url":          url,
        "technologies": [],
        "headers":      {},
        "security":     {},
        "meta":         {},
    }

    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
            timeout=15,
            allow_redirects=True
        )
        result["final_url"]   = r.url
        result["status_code"] = r.status_code
        hdrs = dict(r.headers)

        # Capture relevant headers
        RELEVANT = {
            "Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
            "CF-Ray", "Via", "X-Cache", "X-CDN", "Set-Cookie",
        }
        result["headers"] = {k: v for k, v in hdrs.items() if k in RELEVANT}

        techs = []
        html_lower = r.text.lower()
        soup = BeautifulSoup(r.text, "lxml")

        # Server/language from headers
        server  = hdrs.get("Server", "").lower()
        powered = hdrs.get("X-Powered-By", "").lower()
        for kw, name in [("apache","Apache"), ("nginx","Nginx"), ("iis","Microsoft IIS"),
                         ("litespeed","LiteSpeed"), ("openresty","OpenResty"), ("caddy","Caddy")]:
            if kw in server:
                techs.append({"name": name, "category": "Web Server", "confidence": "High"})
        if "php"    in powered: techs.append({"name": "PHP",    "category": "Language",  "confidence": "High"})
        if "asp.net" in powered: techs.append({"name": "ASP.NET","category": "Framework","confidence": "High"})
        if "cf-ray" in {k.lower() for k in hdrs}:
            techs.append({"name": "Cloudflare", "category": "CDN/WAF", "confidence": "High"})

        # CMS, JS frameworks, analytics
        for name, pats in CMS_PATTERNS.items():
            if any(p in html_lower for p in pats):
                techs.append({"name": name, "category": "CMS", "confidence": "High"})
        for name, pats in JS_PATTERNS.items():
            if any(p in html_lower for p in pats):
                techs.append({"name": name, "category": "JS Framework", "confidence": "Medium"})
        for name, pats in ANALYTICS_PATTERNS.items():
            if any(p in html_lower for p in pats):
                techs.append({"name": name, "category": "Analytics", "confidence": "High"})

        # Security headers grading
        present, missing = {}, []
        for h in SECURITY_HEADERS:
            if h in hdrs:
                present[h] = hdrs[h]
            else:
                missing.append(h)
        score = len(present)
        grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
        result["security"] = {
            "score":   f"{score}/{len(SECURITY_HEADERS)}",
            "grade":   grade,
            "present": present,
            "missing": missing,
        }

        # Meta tags
        for m in soup.find_all("meta"):
            name = (m.get("name", "") or m.get("property", "")).lower()
            content = m.get("content", "")
            if name and content:
                result["meta"][name] = content[:200]

        result["title"]       = (soup.title.string.strip() if soup.title else "")
        result["description"] = result["meta"].get("description", "")
        result["technologies"] = techs

        # External links count
        all_links = [a.get("href", "") for a in soup.find_all("a", href=True)]
        ext = {l for l in all_links if l.startswith("http") and urlparse(url).netloc not in l}
        result["external_links_count"]  = len(ext)
        result["external_links_sample"] = list(ext)[:8]

    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 12. THREAT INTELLIGENCE (OTX · URLhaus · MalwareBazaar · ThreatFox)
# ══════════════════════════════════════════════════════════════════════════════

def _ioc_type(ioc: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc) or re.match(r"^[a-fA-F0-9]{40}$", ioc) or re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "hash"
    if re.match(r"^https?://", ioc):
        return "url"
    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "unknown"


def threat_intel_lookup(ioc: str) -> dict:
    """
    Multi-source threat intel IOC enrichment.
    Sources: AlienVault OTX · URLhaus · MalwareBazaar · ThreatFox · urlscan.io · CIRCL
    Supports: IP · Domain · URL · MD5/SHA1/SHA256 hash
    All sources are FREE — no API key required.
    """
    ioc = ioc.strip()
    ioc_type = _ioc_type(ioc)
    result = {
        "ioc":        ioc,
        "type":       ioc_type,
        "detections": [],
        "reputation": "UNKNOWN",
        "risk_score": 0,
    }

    # ── AlienVault OTX (free public API — no key needed for public indicators) ─
    try:
        type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
        otx_type = type_map.get(ioc_type, "domain")
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general",
            headers={
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "application/json",
                # OTX public endpoint works without key; key only needed for private feeds
            },
            timeout=12
        )
        if r.status_code == 200:
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            reputation  = d.get("reputation", 0)
            result["otx"] = {
                "pulse_count":      pulse_count,
                "reputation":       reputation,
                "malware_families": d.get("malware_families", []),
                "pulse_names":      [p.get("name", "") for p in
                                     d.get("pulse_info", {}).get("pulses", [])[:6]],
            }
            if pulse_count > 0:
                result["detections"].append({
                    "source": "AlienVault OTX",
                    "detected": True,
                    "detail": f"{pulse_count} threat pulse(s)",
                })
            elif reputation < -1:
                result["detections"].append({
                    "source": "AlienVault OTX",
                    "detected": True,
                    "detail": f"Negative reputation score: {reputation}",
                })
    except Exception:
        pass

    # ── URLhaus (IPs and domains/URLs) ────────────────────────────────────────
    if ioc_type in ("url", "domain", "ip"):
        try:
            payload = {"url": ioc} if ioc_type == "url" else {"host": ioc}
            r = requests.post(
                "https://urlhaus-api.abuse.ch/v1/lookup/",
                data=payload,
                headers={"User-Agent": random.choice(USER_AGENTS)},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "is_listed":
                    result["urlhaus"] = {
                        "status":     "MALICIOUS",
                        "threat":     d.get("threat", ""),
                        "urls_count": len(d.get("urls", [])),
                        "date_added": d.get("date_added", ""),
                        "tags":       d.get("tags", []),
                    }
                    result["detections"].append({
                        "source": "URLhaus",
                        "detected": True,
                        "detail": d.get("threat", "Listed as malicious"),
                    })
                else:
                    result["urlhaus"] = {"status": "CLEAN"}
        except Exception:
            pass

    # ── MalwareBazaar (hash lookups) ──────────────────────────────────────────
    if ioc_type == "hash":
        try:
            r = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": ioc},
                headers={"User-Agent": random.choice(USER_AGENTS)},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    sample = d.get("data", [{}])[0]
                    result["malwarebazaar"] = {
                        "status":     "MALICIOUS",
                        "file_name":  sample.get("file_name", ""),
                        "file_type":  sample.get("file_type", ""),
                        "signature":  sample.get("signature", ""),
                        "first_seen": sample.get("first_seen", ""),
                        "tags":       sample.get("tags", []),
                    }
                    result["detections"].append({
                        "source": "MalwareBazaar",
                        "detected": True,
                        "detail": sample.get("signature", "Known malware sample"),
                    })
        except Exception:
            pass

    # ── ThreatFox (IPs & domains) ─────────────────────────────────────────────
    if ioc_type in ("ip", "domain"):
        try:
            r = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc},
                headers={"User-Agent": random.choice(USER_AGENTS)},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    iocs = d.get("data", [])[:5]
                    result["threatfox"] = [{
                        "ioc":         i.get("ioc_value"),
                        "threat_type": i.get("threat_type"),
                        "malware":     i.get("malware"),
                        "first_seen":  i.get("first_seen"),
                        "tags":        i.get("tags", []),
                    } for i in iocs]
                    if iocs:
                        result["detections"].append({
                            "source": "ThreatFox",
                            "detected": True,
                            "detail": f"{len(iocs)} ThreatFox match(es)",
                        })
        except Exception:
            pass

    # ── urlscan.io (FREE, no API key, domain/IP/URL search) ───────────────────
    if ioc_type in ("domain", "ip", "url"):
        try:
            search_q = f"domain:{ioc}" if ioc_type == "domain" else \
                       f"ip:{ioc}"     if ioc_type == "ip"     else \
                       f"page.url:{ioc}"
            r = requests.get(
                f"https://urlscan.io/api/v1/search/?q={search_q}&size=5",
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "application/json",
                },
                timeout=12
            )
            if r.status_code == 200:
                data = r.json()
                results_list = data.get("results", [])
                malicious_count = sum(
                    1 for res in results_list
                    if res.get("verdicts", {}).get("overall", {}).get("malicious", False)
                )
                score_max = max(
                    (res.get("verdicts", {}).get("overall", {}).get("score", 0)
                     for res in results_list),
                    default=0
                )
                result["urlscan"] = {
                    "total_scans":    len(results_list),
                    "malicious_scans": malicious_count,
                    "max_score":       score_max,
                }
                if malicious_count > 0 or score_max >= 50:
                    result["detections"].append({
                        "source": "urlscan.io",
                        "detected": True,
                        "detail": f"{malicious_count} malicious scan(s), max score {score_max}",
                    })
        except Exception:
            pass

    # ── CIRCL passive DNS / hash lookup (free, no key) ────────────────────────
    if ioc_type == "hash":
        try:
            r = requests.get(
                f"https://hashlookup.circl.lu/lookup/md5/{ioc}" if len(ioc) == 32 else
                f"https://hashlookup.circl.lu/lookup/sha1/{ioc}" if len(ioc) == 40 else
                f"https://hashlookup.circl.lu/lookup/sha256/{ioc}",
                headers=_hdrs(), timeout=8
            )
            if r.status_code == 200:
                d = r.json()
                ks = d.get("KnownMalicious", 0)
                result["circl"] = {
                    "file_name": d.get("FileName", ""),
                    "known_malicious": bool(ks),
                }
                if ks:
                    result["detections"].append({
                        "source": "CIRCL HashLookup",
                        "detected": True,
                        "detail": "Hash flagged as known malicious",
                    })
        except Exception:
            pass

    # ── abuse.ch WHOIS-style domain check (free) ──────────────────────────────
    if ioc_type == "domain":
        try:
            r = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": f"%.{ioc}"},
                headers={"User-Agent": random.choice(USER_AGENTS)},
                timeout=8
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok" and d.get("data"):
                    result["detections"].append({
                        "source": "ThreatFox (wildcard)",
                        "detected": True,
                        "detail": f"Subdomain of {ioc} seen in ThreatFox",
                    })
        except Exception:
            pass

    # ── Final scoring ─────────────────────────────────────────────────────────
    n = len(result["detections"])
    result["reputation"] = (
        "🔴 MALICIOUS"  if n >= 3 else
        "🟠 SUSPICIOUS" if n >= 1 else
        "🟢 CLEAN"
    )
    result["risk_score"] = min(100, n * 25)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 13. SOCIAL MEDIA LINK EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

SOCIAL_PATTERNS = {
    "Twitter/X":    r'(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,50})',
    "LinkedIn":     r'linkedin\.com/(?:company|in)/([A-Za-z0-9\-\_]+)',
    "Facebook":     r'facebook\.com/([A-Za-z0-9\.]+)',
    "Instagram":    r'instagram\.com/([A-Za-z0-9_\.]+)',
    "GitHub":       r'github\.com/([A-Za-z0-9\-]+)',
    "YouTube":      r'youtube\.com/(?:@|channel/|user/)([A-Za-z0-9_\-]+)',
    "TikTok":       r'tiktok\.com/@([A-Za-z0-9_\.]+)',
    "Telegram":     r't\.me/([A-Za-z0-9_]+)',
    "Discord":      r'discord\.gg/([A-Za-z0-9]+)',
    "Pinterest":    r'pinterest\.com/([A-Za-z0-9_]+)',
}

def social_media_from_domain(domain: str) -> dict:
    """
    Crawl a domain's homepage, contact page, and about page to extract
    all linked social media profiles. No API key required.
    Returns found profiles grouped by platform.
    """
    domain = _clean_domain(domain)
    base_url = f"https://{domain}"
    pages_to_check = [
        base_url,
        f"{base_url}/contact",
        f"{base_url}/about",
        f"{base_url}/about-us",
        f"{base_url}/contact-us",
        f"{base_url}/team",
    ]

    all_html = ""
    found_pages = []

    for url in pages_to_check:
        try:
            r = requests.get(
                url,
                headers={
                    "User-Agent": random.choice(USER_AGENTS),
                    "Accept": "text/html",
                },
                timeout=10,
                allow_redirects=True
            )
            if r.status_code == 200:
                all_html += r.text
                found_pages.append(url)
        except Exception:
            continue

    profiles = {}
    seen_urls = set()

    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, all_html, re.IGNORECASE)
        platform_urls = []
        for handle in matches:
            # Build full URL
            if platform == "Twitter/X":
                full = f"https://twitter.com/{handle}"
            elif platform == "LinkedIn":
                full = f"https://linkedin.com/company/{handle}" if "/company/" in handle else f"https://linkedin.com/in/{handle}"
            elif platform == "Facebook":
                full = f"https://facebook.com/{handle}"
            elif platform == "Instagram":
                full = f"https://instagram.com/{handle}"
            elif platform == "GitHub":
                full = f"https://github.com/{handle}"
            elif platform == "YouTube":
                full = f"https://youtube.com/@{handle}"
            elif platform == "TikTok":
                full = f"https://tiktok.com/@{handle}"
            elif platform == "Telegram":
                full = f"https://t.me/{handle}"
            elif platform == "Discord":
                full = f"https://discord.gg/{handle}"
            elif platform == "Pinterest":
                full = f"https://pinterest.com/{handle}"
            else:
                full = handle

            if full not in seen_urls:
                seen_urls.add(full)
                platform_urls.append({"handle": handle, "url": full})

        if platform_urls:
            profiles[platform] = platform_urls

    # Also extract all external links not on same domain
    soup = BeautifulSoup(all_html, "lxml")
    external_links = []
    seen_ext = set()
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        if href.startswith("http") and domain not in href:
            clean = href.split("?")[0].rstrip("/")
            if clean not in seen_ext and len(clean) > 10:
                seen_ext.add(clean)
                external_links.append({
                    "url": clean,
                    "text": a.get_text(strip=True)[:60],
                })

    return {
        "domain":          domain,
        "pages_crawled":   found_pages,
        "social_profiles": profiles,
        "total_found":     len(seen_urls),
        "external_links":  external_links[:30],
    }


# ══════════════════════════════════════════════════════════════════════════════
# 14. ROBOTS.TXT & SITEMAP ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def robots_and_sitemap(domain: str) -> dict:
    """
    Fetch and analyse robots.txt and sitemap.xml.
    Reveals disallowed paths (often sensitive admin areas), sitemap URLs,
    and crawl directives — valuable passive recon without active scanning.
    """
    domain = _clean_domain(domain)
    base = f"https://{domain}"
    result = {
        "domain":     domain,
        "robots":     {},
        "sitemaps":   [],
        "disallowed": [],
        "allowed":    [],
        "user_agents": [],
    }

    # ── robots.txt ────────────────────────────────────────────────────────────
    try:
        r = requests.get(
            f"{base}/robots.txt",
            headers={"User-Agent": random.choice(USER_AGENTS)},
            timeout=10
        )
        if r.status_code == 200:
            raw = r.text
            result["robots"]["raw"]  = raw[:3000]
            result["robots"]["size"] = len(raw)

            disallowed, allowed, sitemaps, agents = [], [], [], []
            current_agent = "*"

            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    agents.append(agent)
                    current_agent = agent
                elif line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append({"path": path, "agent": current_agent})
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        allowed.append({"path": path, "agent": current_agent})
                elif line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    sitemaps.append(sm)

            result["disallowed"]  = disallowed[:50]
            result["allowed"]     = allowed[:20]
            result["user_agents"] = list(set(agents))

            # Flag interesting disallowed paths
            sensitive_keywords = [
                "admin","login","api","backup","config","db","database",
                "secret","private","internal","staging","dev","test","wp-admin",
                "phpmyadmin","cpanel","dashboard","portal","manage",
            ]
            result["sensitive_paths"] = [
                d for d in disallowed
                if any(kw in d["path"].lower() for kw in sensitive_keywords)
            ]

            # Add sitemap from robots.txt
            for sm in sitemaps:
                if sm not in result["sitemaps"]:
                    result["sitemaps"].append(sm)

    except Exception:
        result["robots"]["error"] = "Could not fetch robots.txt"

    # ── sitemap.xml ───────────────────────────────────────────────────────────
    sitemap_urls_to_try = [
        f"{base}/sitemap.xml",
        f"{base}/sitemap_index.xml",
        f"{base}/sitemap-index.xml",
        f"{base}/wp-sitemap.xml",
    ]
    # Also try URLs found in robots.txt
    sitemap_urls_to_try += [s for s in result["sitemaps"] if s not in sitemap_urls_to_try]

    all_sitemap_entries = []
    for sm_url in sitemap_urls_to_try[:5]:
        try:
            r = requests.get(
                sm_url,
                headers={"User-Agent": random.choice(USER_AGENTS)},
                timeout=10
            )
            if r.status_code == 200 and "<" in r.text:
                soup = BeautifulSoup(r.text, "lxml-xml") if "xml" in r.headers.get("content-type","") else BeautifulSoup(r.text, "lxml")
                locs = [loc.get_text(strip=True) for loc in soup.find_all("loc")]
                all_sitemap_entries.extend(locs)
                if sm_url not in result["sitemaps"]:
                    result["sitemaps"].append(sm_url)
        except Exception:
            continue

    result["sitemap_urls"]       = list(set(all_sitemap_entries))[:100]
    result["sitemap_page_count"] = len(set(all_sitemap_entries))

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 15. ASN / BGP REPUTATION LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def asn_reputation(target: str) -> dict:
    """
    Look up ASN (Autonomous System Number) information and reputation.
    Sources: bgpview.io (free) + ipinfo.io (free basic tier)
    Input: IP address or domain name.
    """
    target = _clean_domain(target)
    ip = target
    result = {"target": target, "ip": ip}

    # Resolve domain → IP if needed
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        try:
            ip = socket.gethostbyname(target)
            result["ip"] = ip
            result["resolved_from"] = target
        except Exception:
            result["error"] = "Could not resolve hostname"
            return result

    # ── bgpview.io — free, no auth ────────────────────────────────────────────
    try:
        r = requests.get(
            f"https://api.bgpview.io/ip/{ip}",
            headers=_hdrs(), timeout=12
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            prefixes = d.get("prefixes", [])
            asns = []
            for prefix in prefixes[:5]:
                asn_data = prefix.get("asn", {})
                asns.append({
                    "asn":         f"AS{asn_data.get('asn','')}",
                    "name":        asn_data.get("name", ""),
                    "description": asn_data.get("description", ""),
                    "country":     asn_data.get("country_code", ""),
                    "prefix":      prefix.get("prefix", ""),
                    "rir":         prefix.get("rir_allocation", {}).get("rir_name", ""),
                })
            result["bgpview"] = {
                "asns":      asns,
                "ptr":       d.get("ptr_record", ""),
                "rir_alloc": prefixes[0].get("rir_allocation", {}) if prefixes else {},
            }
    except Exception:
        pass

    # ── ipinfo.io — free basic tier ───────────────────────────────────────────
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            result["ipinfo"] = {
                "org":      d.get("org", ""),
                "asn":      d.get("org", "").split()[0] if d.get("org") else "",
                "hostname": d.get("hostname", ""),
                "city":     d.get("city", ""),
                "region":   d.get("region", ""),
                "country":  d.get("country", ""),
                "timezone": d.get("timezone", ""),
            }
    except Exception:
        pass

    # ── Abuse DB check via bgpview ─────────────────────────────────────────────
    try:
        asn_num = None
        if result.get("bgpview", {}).get("asns"):
            raw_asn = result["bgpview"]["asns"][0]["asn"]
            asn_num = raw_asn.replace("AS", "")

        if asn_num:
            r = requests.get(
                f"https://api.bgpview.io/asn/{asn_num}",
                headers=_hdrs(), timeout=10
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                result["asn_details"] = {
                    "asn":          f"AS{asn_num}",
                    "name":         d.get("name", ""),
                    "description":  d.get("description_short", ""),
                    "country":      d.get("country_code", ""),
                    "website":      d.get("website", ""),
                    "email":        d.get("email_contacts", []),
                    "abuse_email":  d.get("abuse_contacts", []),
                    "rir":          d.get("rir_allocation", {}).get("rir_name", ""),
                    "allocated":    d.get("rir_allocation", {}).get("date_allocated", ""),
                    "prefixes_v4":  d.get("prefixes_v4_count", 0),
                }
    except Exception:
        pass

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 16. DNS ZONE TRANSFER ATTEMPT (educational — almost always fails, shows concept)
# ══════════════════════════════════════════════════════════════════════════════

def zone_transfer_check(domain: str) -> dict:
    """
    Attempt DNS zone transfer (AXFR) against all discovered nameservers.
    Zone transfers expose ALL DNS records of a domain — a critical misconfiguration.
    In practice almost always refused, but the attempt itself is educational
    and any success is a CRITICAL finding.
    No external APIs — uses raw socket DNS queries via dnspython-compatible approach.
    """
    domain = _clean_domain(domain)
    result = {
        "domain":      domain,
        "nameservers": [],
        "attempts":    [],
        "vulnerable":  False,
        "records":     [],
    }

    # Get nameservers first via DoH
    try:
        r = requests.get(
            f"https://dns.google/resolve?name={domain}&type=NS",
            headers=_hdrs(), timeout=8
        )
        if r.status_code == 200:
            ns_list = [a.get("data","").rstrip(".") for a in r.json().get("Answer",[])]
            result["nameservers"] = ns_list
    except Exception:
        pass

    if not result["nameservers"]:
        result["error"] = "Could not resolve nameservers"
        return result

    # Attempt AXFR via dig-style TCP connection to port 53
    for ns in result["nameservers"][:4]:
        attempt = {"nameserver": ns, "status": "REFUSED", "error": ""}
        try:
            ns_ip = socket.gethostbyname(ns)
            # Build minimal AXFR query packet
            import struct
            txid   = random.randint(1000, 65000)
            # DNS header: ID, flags (standard query), QDCOUNT=1, AN/NS/AR=0
            header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
            # Question: domain name encoded + QTYPE=252 (AXFR) + QCLASS=1 (IN)
            qname = b""
            for label in domain.split("."):
                qname += bytes([len(label)]) + label.encode()
            qname += b"\x00"
            question = qname + struct.pack(">HH", 252, 1)
            packet   = header + question
            # TCP DNS: 2-byte length prefix
            tcp_pkt  = struct.pack(">H", len(packet)) + packet

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((ns_ip, 53))
            sock.sendall(tcp_pkt)
            response = sock.recv(4096)
            sock.close()

            if len(response) > 4:
                # Parse response flags: byte 2-3
                flags  = struct.unpack(">H", response[2:4])[0]
                rcode  = flags & 0x000F
                # rcode 0 = NOERROR (zone transfer allowed — CRITICAL)
                # rcode 5 = REFUSED (normal)
                # rcode 9 = NOTAUTH
                if rcode == 0 and len(response) > 50:
                    attempt["status"] = "VULNERABLE — AXFR ALLOWED"
                    result["vulnerable"] = True
                elif rcode == 5:
                    attempt["status"] = "REFUSED (secure)"
                elif rcode == 9:
                    attempt["status"] = "NOT AUTHORITATIVE"
                else:
                    attempt["status"] = f"RCODE {rcode}"
        except socket.timeout:
            attempt["status"] = "TIMEOUT"
        except ConnectionRefusedError:
            attempt["status"] = "PORT 53 CLOSED"
        except Exception as e:
            attempt["status"] = "ERROR"
            attempt["error"]  = str(e)[:100]

        result["attempts"].append(attempt)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# 17. OPEN REDIRECT & SECURITY HEADERS QUICK AUDIT
# ══════════════════════════════════════════════════════════════════════════════

def security_audit(domain: str) -> dict:
    """
    Quick passive security audit of a domain:
    - Full HTTP security header check with grades
    - Cookie security flags (HttpOnly, Secure, SameSite)
    - HTTPS redirect check
    - Mixed content hints from HTML
    - HSTS preload check via hstspreload.org
    - Server version disclosure check
    Returns a scored security report card.
    """
    domain = _clean_domain(domain)
    http_url  = f"http://{domain}"
    https_url = f"https://{domain}"
    result = {
        "domain":       domain,
        "score":        0,
        "max_score":    100,
        "grade":        "F",
        "checks":       [],
        "headers":      {},
        "cookies":      [],
        "hsts_preload": False,
    }

    def add_check(name, passed, detail, points):
        result["checks"].append({
            "check":  name,
            "passed": passed,
            "detail": detail,
            "points": points if passed else 0,
        })
        if passed:
            result["score"] += points

    # ── HTTPS redirect ────────────────────────────────────────────────────────
    try:
        r_http = requests.get(http_url, headers={"User-Agent": random.choice(USER_AGENTS)},
                              timeout=8, allow_redirects=False)
        redirects_to_https = (
            r_http.status_code in (301, 302, 307, 308) and
            r_http.headers.get("Location","").startswith("https")
        )
        add_check("HTTP→HTTPS Redirect", redirects_to_https,
                  f"HTTP status {r_http.status_code}, Location: {r_http.headers.get('Location','')}",
                  10)
    except Exception as e:
        add_check("HTTP→HTTPS Redirect", False, str(e)[:60], 10)

    # ── Fetch HTTPS response ──────────────────────────────────────────────────
    hdrs = {}
    cookies_raw = []
    try:
        r = requests.get(https_url, headers={"User-Agent": random.choice(USER_AGENTS)},
                         timeout=12, allow_redirects=True)
        hdrs = dict(r.headers)
        result["headers"] = {k: v[:200] for k, v in hdrs.items()}
        cookies_raw = r.cookies
        html_content = r.text
    except Exception as e:
        result["error"] = f"Could not reach {https_url}: {e}"
        return result

    # ── Security headers ──────────────────────────────────────────────────────
    HEADER_CHECKS = [
        ("Strict-Transport-Security", "HSTS",                     15),
        ("Content-Security-Policy",   "CSP",                      15),
        ("X-Frame-Options",           "Clickjacking Protection",  10),
        ("X-Content-Type-Options",    "MIME Sniffing Protection",  5),
        ("Referrer-Policy",           "Referrer Policy",           5),
        ("Permissions-Policy",        "Permissions Policy",        5),
        ("X-XSS-Protection",          "XSS Protection Header",     5),
    ]
    headers_lower = {k.lower(): v for k, v in hdrs.items()}
    for header, name, pts in HEADER_CHECKS:
        present = header.lower() in headers_lower
        add_check(f"{name} ({header})", present,
                  hdrs.get(header, "MISSING")[:100], pts)

    # ── Server/tech disclosure ────────────────────────────────────────────────
    server = hdrs.get("Server", hdrs.get("X-Powered-By", ""))
    discloses_version = bool(re.search(r"\d+\.\d+", server))
    add_check("No Server Version Disclosure", not discloses_version,
              f"Server: {server}" if server else "Server header not present", 10)

    # ── Cookie security ───────────────────────────────────────────────────────
    cookie_list = []
    for cookie in cookies_raw:
        c = {
            "name":      cookie.name,
            "secure":    cookie.secure,
            "httponly":  cookie.has_nonstandard_attr("HttpOnly"),
            "samesite":  cookie._rest.get("SameSite", "Not set"),
        }
        cookie_list.append(c)
    result["cookies"] = cookie_list
    all_cookies_secure = all(c["secure"] for c in cookie_list) if cookie_list else True
    add_check("All Cookies Secure Flag", all_cookies_secure,
              f"{len(cookie_list)} cookie(s) checked", 10)

    # ── HSTS Preload check via hstspreload.org ────────────────────────────────
    try:
        r2 = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={domain}",
            headers=_hdrs(), timeout=8
        )
        if r2.status_code == 200:
            status = r2.json().get("status", "")
            preloaded = status == "preloaded"
            result["hsts_preload"] = preloaded
            add_check("HSTS Preload List", preloaded,
                      f"Preload status: {status}", 10)
    except Exception:
        pass

    # ── Final grade ───────────────────────────────────────────────────────────
    s = result["score"]
    result["grade"] = ("A+" if s >= 95 else "A" if s >= 85 else "B" if s >= 70
                        else "C" if s >= 55 else "D" if s >= 40 else "F")

    return result
