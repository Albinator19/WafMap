from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import os

MAX_PAGES = 150 
SKIP_EXT = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.pdf', '.zip']

def is_valid_scope(url, base_domain):
    try:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != base_domain:
            return False
        if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXT):
            return False
        if parsed.scheme in ['mailto', 'javascript', 'tel']:
            return False
        return True
    except:
        return False

def get_structure_hash(url, method, params):
    parsed = urlparse(url)
    path = parsed.path
    param_keys = sorted(params)
    return f"{method}:{path}:{','.join(param_keys)}"

def load_wordlist(filename="payloads/common.txt"):
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return []
    except: return []

def fuzz_directories(engine, base_url):
    print(f"    [*] Lancement du Fuzzing de répertoires...")
    discovered = []
    
    wordlist = load_wordlist()
    if not wordlist:
        print("    [!] Pas de wordlist 'common.txt', utilisation liste par défaut.")
        wordlist = ['admin', 'login', 'test', 'api', 'backup', 'config', 'dashboard', 'uploads']

    for path in wordlist:
        url = urljoin(base_url, path)
        
        resp = engine._send_request(url, method="HEAD") 

        if resp and resp.status_code in [200, 301, 302, 401, 403]:
            print(f"    [+] Répertoire découvert : {url} (Code {resp.status_code})")
            discovered.append(url)
            
    return discovered

def fetch_robots_sitemap(engine, base_url):
    urls = []
    
    resp = engine._send_request(urljoin(base_url, "/robots.txt"))
    if resp and resp.status_code == 200:
        print("    [+] robots.txt détecté")
        for line in resp.text.splitlines():
            if "Disallow:" in line or "Allow:" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    path = parts[1].strip()
                    urls.append(urljoin(base_url, path))
    
    resp = engine._send_request(urljoin(base_url, "/sitemap.xml"))
    if resp and resp.status_code == 200:
        print("    [+] sitemap.xml détecté")
        try:
            soup = BeautifulSoup(resp.text, 'xml')
            for loc in soup.find_all('loc'):
                urls.append(loc.text)
        except: pass
            
    return urls

def crawl_target(engine, api_seeds=None):
    target = engine.config['target']
    parsed_target = urlparse(target)
    base_domain = parsed_target.netloc
    
    print(f"[CRAWL] Analyse approfondie de {target} ({MAX_PAGES} pages max)...")
    
    queue = [target]
    
    queue += fetch_robots_sitemap(engine, target)
    
    queue += fuzz_directories(engine, target)
    
    visited_urls = set()
    structure_hashes = set() 
    injection_points = []

    while queue and len(visited_urls) < MAX_PAGES:
        curr_url = queue.pop(0)
        
        if curr_url in visited_urls: continue
        visited_urls.add(curr_url)
        
        if not is_valid_scope(curr_url, base_domain): continue

        resp = engine._send_request(curr_url)
        if not resp or 'text/html' not in resp.headers.get('Content-Type', ''): continue

        soup = BeautifulSoup(resp.text, 'html.parser')

        for a in soup.find_all('a', href=True):
            abs_url = urljoin(curr_url, a['href']).split('#')[0]
            if is_valid_scope(abs_url, base_domain) and abs_url not in visited_urls:
                queue.append(abs_url)

        parsed = urlparse(curr_url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            params = list(qs.keys())
            
            sig = get_structure_hash(curr_url, 'GET', params)
            if sig not in structure_hashes:
                structure_hashes.add(sig)
                injection_points.append({
                    'url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    'method': 'GET',
                    'parameters': params
                })

        for form in soup.find_all('form'):
            action = urljoin(curr_url, form.get('action') or '')
            method = form.get('method', 'get').upper()
            inputs = [i.get('name') for i in form.find_all(['input', 'textarea']) if i.get('name')]
            
            if inputs:
                sig = get_structure_hash(action, method, inputs)
                if sig not in structure_hashes:
                    structure_hashes.add(sig)
                    injection_points.append({
                        'url': action,
                        'method': method,
                        'parameters': inputs
                    })

    print(f"[CRAWL] Terminé. {len(injection_points)} points d'injection identifiés.")
    return injection_points
