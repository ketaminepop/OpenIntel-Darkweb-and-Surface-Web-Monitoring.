import requests
import random, re
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
]

SEARCH_ENGINE_ENDPOINTS = [
    "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}",
    "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}",
    "http://darkhuntyla64h75a3re5e2l3367lqn7ltmdzpgmr6b4nbz3q2iaxrid.onion/search?q={query}",
    "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}",
    "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}",
    "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}",
    "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}",
    "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}",
    "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}",
    "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}",
    "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}",
    "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}",
    "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}",
    "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}",
    "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}",
    "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}",
    "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}",
]

TOR_PROXIES = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}

def extract_onion_url(href):
    if not href: return None
    if 'http' in href and '.onion' in href:
        m = re.search(r'(https?://[a-z0-9]{16,56}\.onion[^\s&\'"<>]*)', href)
        if m: return m.group(1).rstrip('/')
    return None

def parse_ahmia(soup):
    results = []
    for r in soup.select('li.result'):
        try:
            cite = r.select_one('cite')
            if cite:
                url = cite.get_text(strip=True).split()[0]
                if not url.startswith('http'): url = 'http://' + url
                h4 = r.select_one('h4')
                results.append({"title": h4.get_text(strip=True) if h4 else url, "link": url})
        except Exception: continue
    return results

def parse_generic(soup, engine_domain):
    results, seen = [], set()
    skip = {'home','about','next','previous','search','back','login','register','prev'}
    for a in soup.find_all('a', href=True):
        try:
            title = a.get_text(strip=True)
            if not title or len(title) < 5 or title.lower() in skip: continue
            url = extract_onion_url(a['href'])
            if url and engine_domain not in url and url not in seen:
                seen.add(url); results.append({"title": title, "link": url})
        except Exception: continue
    return results

def fetch_engine(endpoint, query):
    try:
        resp = requests.get(endpoint.format(query=query),
                            headers={"User-Agent": random.choice(USER_AGENTS)},
                            proxies=TOR_PROXIES, timeout=30)
        if resp.status_code != 200: return []
        soup = BeautifulSoup(resp.text, "lxml")
        domain = urlparse(endpoint).netloc.replace('.onion','')
        if 'juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd' in endpoint:
            return parse_ahmia(soup)
        return parse_generic(soup, domain)
    except Exception: return []

def get_search_results(query, max_workers=12):
    all_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for f in as_completed([ex.submit(fetch_engine, ep, query) for ep in SEARCH_ENGINE_ENDPOINTS]):
            try: all_results.extend(f.result())
            except Exception: pass
    seen, unique = set(), []
    for r in all_results:
        if r.get("link") and r["link"] not in seen:
            seen.add(r["link"]); unique.append(r)
    return unique
