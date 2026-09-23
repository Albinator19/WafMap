import requests
import time
import urllib3
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .detection import detect_waf
from .crawler import crawl_target
from .sqli import run_sqli_test
from .xss import run_xss_test
from .ssti import run_ssti_test
from .lfi import run_lfi_test
from .ssrf import run_ssrf_test
from .port_scanner import scan_ports
from .subdomain import scan_subdomains
from .api_discovery import detect_api
from .cve_lookup import search_cve, print_cve_results
from .report import generate_report
from .cmdi import run_cmdi_test
from .nosqli import run_nosqli_test
from .csrf import run_csrf_test
from .idor import run_idor_test
from .smuggling import run_smuggling_test
from .ratelimiter import RateLimiter
from .auth import perform_login

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class Engine:
    def __init__(self, args):
        self.config = self._load_config(args)

        self.session = requests.Session()
        self.session.trust_env = False

        ua = self.config['user_agent'] if self.config['user_agent'] else 'WAFMap/2.0'
        self.session.headers.update({
            'User-Agent': ua,
            'Connection': 'close',
            'Accept': '*/*'
        })

        if self.config['proxy']:
            self.session.proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }
            if self.config['verbose']:
                print(f"[CONF] Proxy configuré : {self.config['proxy']}")

        if self.config['headers_file']:
            self._load_custom_headers(self.config['headers_file'])

        adapter = HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.second_session = None
        if self.config.get('second_session_cookie') or self.config.get('second_session_header'):
            self.second_session = requests.Session()
            self.second_session.trust_env = False
            self.second_session.headers.update({'User-Agent': ua, 'Accept': '*/*'})
            if self.config.get('second_session_cookie'):
                self.second_session.headers.update({'Cookie': self.config['second_session_cookie']})
            if self.config.get('second_session_header'):
                k, _, v = self.config['second_session_header'].partition(':')
                if k and v:
                    self.second_session.headers.update({k.strip(): v.strip()})

        self.verify_ssl = self.config.get('verify_ssl_flag', False)
        self.vulnerabilities = []
        self.recon_findings = []
        self.bypass_findings = []
        self._bypass_cache = {}
        self.detected_waf_name = None
        self.waf_is_blocking = True
        self.csrf_token = None
        self._confirmed_vectors = set()

        self.rate_limiter = RateLimiter(self.config.get('rate_limit'))

    def _load_config(self, args):
        return {
            'target': args.target.rstrip('/') if args.target else None,
            'target_list': getattr(args, 'target_list', None),
            'threads': min(args.threads, 50),
            'timeout': args.timeout,
            'verbose': args.verbose,
            'waf_only': args.waf_only,
            'crawl': args.crawl,
            'waf_bypass': args.waf_bypass,
            'category': args.category,
            'level': args.level,
            'output': args.output,
            'format': args.format,
            'ports': args.ports,
            'subdomains': args.subdomains,
            'api_scan': args.api_scan,
            'cve': args.cve,
            'proxy': args.proxy,
            'user_agent': args.user_agent,
            'headers_file': args.headers,
            'data': args.data,
            'match_code': args.match_code,
            'match_text': args.match_text,
            'rate_limit': getattr(args, 'rate_limit', None),
            'allowed_domains': [d.strip().lower() for d in args.allowed_domains.split(',')] if getattr(args, 'allowed_domains', None) else None,
            'login_url': getattr(args, 'login_url', None),
            'login_data': getattr(args, 'login_data', None),
            'login_success_text': getattr(args, 'login_success_text', None),
            'second_session_cookie': getattr(args, 'second_session_cookie', None),
            'second_session_header': getattr(args, 'second_session_header', None),
            'verify_ssl_flag': getattr(args, 'verify_ssl', False),
        }


    def is_in_scope(self, url):
        try:
            host = urlparse(url).netloc.split(':')[0].lower()
        except Exception:
            return False

        if self.config['allowed_domains']:
            allowed = self.config['allowed_domains']
        else:
            base_host = urlparse(self.config['target']).netloc.split(':')[0].lower()
            allowed = [base_host]

        for domain in allowed:
            if host == domain or host.endswith('.' + domain):
                return True
        return False

    def _fetch_csrf_token(self, html_text):
        if not html_text:
            return
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            for input_tag in soup.find_all('input', {'type': 'hidden'}):
                name = input_tag.get('name', '').lower()
                value = input_tag.get('value', '')
                if any(x in name for x in ['csrf', 'token', 'nonce', 'user_token']) and value:
                    self.csrf_token = {name: value}
                    if self.config['verbose']:
                        print(f"[CONF] Jeton CSRF trouvé: {name}")
                    return
        except Exception as e:
            if self.config['verbose']:
                print(f"[ERR] Échec du parsing CSRF: {e}")

    def _load_custom_headers(self, filepath):
        if not os.path.exists(filepath):
            print(f"[!] Fichier headers introuvable : {filepath}")
            return
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        self.session.headers.update({k.strip(): v.strip()})
            if self.config['verbose']:
                print(f"[CONF] Headers chargés depuis {filepath}")
        except Exception as e:
            print(f"[!] Erreur lecture headers : {e}")

    def _send_request(self, url, method="GET", data=None, params=None, attempt=1, session=None):
        if method == "GET" and self.config['data'] and data is None:
            method = "POST"
            data = self.config['data']

        if self.config['verbose']:
            print(f"[REQ] {method} {url} | P:{params} D:{data}")

        return self._dispatch(session or self.session, method, url, data=data, params=params, attempt=attempt)

    def _send_request_raw(self, url, method, other_params, target_param, raw_value, session=None):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        clean_others = {k: v for k, v in (other_params or {}).items() if k != target_param}
        other_qs = urlencode(clean_others)

        pair = f"{target_param}={raw_value}"
        body_or_qs = f"{other_qs}&{pair}" if other_qs else pair

        if method == "POST":
            full_url = base
            data = body_or_qs
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        else:
            full_url = f"{base}?{body_or_qs}"
            data = None
            headers = None

        if self.config['verbose']:
            print(f"[REQ-RAW] {method} {full_url if method == 'GET' else base} | BODY:{data}")

        return self._dispatch(session or self.session, method, full_url, data=data, params=None, headers=headers)

    def _dispatch(self, sess, method, url, data=None, params=None, headers=None, attempt=1):
        try:
            self.rate_limiter.wait()

            response = sess.request(
                method, url, data=data, params=params, headers=headers,
                timeout=self.config['timeout'], verify=self.verify_ssl, allow_redirects=True
            )

            if response.status_code in [429, 503] and attempt <= 3:
                time.sleep(2 * attempt)
                return self._dispatch(sess, method, url, data=data, params=params, headers=headers, attempt=attempt + 1)

            return response

        except requests.exceptions.Timeout:
            if self.config['verbose']:
                console.print(f"[bold red][TIMEOUT] {url}[/bold red]")
            return None
        except Exception as e:
            if self.config['verbose']:
                console.print(f"[bold red][ERR] {url}: {e}[/bold red]")
            return None

    def check_custom_validation(self, response):
        if response is None:
            return
        matched = False
        reasons = []

        if self.config['match_code'] and response.status_code == self.config['match_code']:
            matched = True
            reasons.append(f"Code {response.status_code}")

        if self.config['match_text'] and self.config['match_text'] in response.text:
            matched = True
            reasons.append(f"Texte '{self.config['match_text']}' trouvé")

        if matched:
            self.add_vulnerability("CUSTOM CHECK", response.url, self.config['data'] or "GET",
                                    f"Validé: {', '.join(reasons)}", parameter="Manual")


    def is_vector_confirmed(self, type_prefix, url, parameter):
        return (type_prefix, url, parameter) in self._confirmed_vectors

    def add_vulnerability(self, type_, url, payload, details, parameter=None, confidence="Confirmée"):
        for v in self.vulnerabilities:
            if v['type'] == type_ and v['url'] == url and v.get('parameter') == parameter and v['payload'] == payload:
                return

        vuln = {
            "type": type_, "url": url, "parameter": parameter,
            "payload": payload, "details": details,
            "confidence": confidence,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)

        type_prefix = type_.split(' ')[0].split('(')[0].strip()
        self._confirmed_vectors.add((type_prefix, url, parameter))

        border = "red" if confidence == "Confirmée" else "yellow"
        title_prefix = "VULNÉRABILITÉ CONFIRMÉE" if confidence == "Confirmée" else "A VÉRIFIER MANUELLEMENT"

        grid = Table.grid(padding=(0, 1))
        grid.add_column(style="cyan", justify="right")
        grid.add_column(style="white")

        grid.add_row("URL :", url)
        if parameter:
            grid.add_row("Paramètre :", parameter)
        grid.add_row("Payload :", payload)
        grid.add_row("Détails :", details)
        grid.add_row("Confiance :", confidence)

        console.print(Panel(
            grid,
            title=f"[bold {border}]{title_prefix} : {type_}",
            border_style=border,
            expand=False
        ))

    def add_recon_finding(self, type_, url, details):
        self.recon_findings.append({
            "type": type_, "url": url, "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    def add_bypass_finding(self, vtype, url, waf_name, technique, worked, canary_payload):
        entry = {
            "vtype": vtype, "url": url, "waf": waf_name,
            "technique": technique, "worked": worked,
            "canary_payload": canary_payload,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.bypass_findings.append(entry)

        if worked:
            console.print(f"[bold magenta][BYPASS CONFIRMÉ][/bold magenta] {vtype.upper()} sur {url} "
                           f"contourne [green]{waf_name}[/green] via la technique [bold]{technique}[/bold]")
        elif self.config['verbose']:
            print(f"[BYPASS] Aucune technique testée n'a fonctionné pour {vtype} sur {url} ({waf_name}).")

    def get_bypass_technique(self, vtype, url):
        return self._bypass_cache.get((vtype, url))

    def set_bypass_technique(self, vtype, url, technique):
        self._bypass_cache[(vtype, url)] = technique

    def start_scan(self):
        login_result = perform_login(self)

        base_targets = []
        if self.config.get('target_list'):
            try:
                with open(self.config['target_list'], 'r') as f:
                    base_targets = [line.strip().rstrip('/') for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                console.print(f"[bold red][!] Impossible de lire --target-list : {e}[/bold red]")
                return
        elif self.config['target']:
            base_targets = [self.config['target']]
        else:
            console.print("[bold red][!] Aucune cible fournie (--target ou --target-list).[/bold red]")
            return

        for base_target in base_targets:
            self.config['target'] = base_target
            self._scan_single_base_target(base_target)

        total = len(self.vulnerabilities)
        confirmed = len([v for v in self.vulnerabilities if v['confidence'] == 'Confirmée'])
        to_verify = total - confirmed
        bypasses_found = len([b for b in self.bypass_findings if b['worked']])
        console.print(f"\n[*] Scan terminé. {confirmed} vulnérabilité(s) confirmée(s), "
                       f"{to_verify} à vérifier manuellement, {len(self.recon_findings)} finding(s) de reconnaissance, "
                       f"{bypasses_found} technique(s) de bypass WAF confirmée(s).")

        if self.config['output']:
            generate_report(self)

    def _scan_single_base_target(self, base_target):
        console.print(f"[bold blue][*] Démarrage du scan sur [white]{base_target}[/white][/bold blue]")

        target_urls = [base_target]

        if self.config['ports']:
            print("\n=== PHASE: SCAN DE PORTS ===")
            discovered = scan_ports(base_target, self.config['ports'])
            target_urls.extend([u for u in discovered if self.is_in_scope(u)])

        if self.config['subdomains']:
            print("\n=== PHASE: SOUS-DOMAINES ===")
            subs = scan_subdomains(base_target)
            for sub in subs:
                candidate = f"http://{sub}" if not sub.startswith("http") else sub
                if self.is_in_scope(candidate):
                    target_urls.append(candidate)
                elif self.config['verbose']:
                    print(f"[SCOPE] Ignoré (hors périmètre) : {candidate}")

        target_urls = sorted(list(set(target_urls)))

        for current_target in target_urls:
            print(f"\n>>> ANALYSE DE : {current_target}")
            original_target_conf = self.config['target']
            clean_url = None

            try:
                parsed = urlparse(current_target)
                self.config['target'] = current_target

                base_method = "POST" if self.config['data'] else "GET"
                resp = self._send_request(current_target, method=base_method, data=self.config['data'])

                if resp is None:
                    print("[!] Cible inaccessible. On passe.")
                    self.config['target'] = original_target_conf
                    continue

                if self.config['match_code'] or self.config['match_text']:
                    self.check_custom_validation(resp)

                self._fetch_csrf_token(resp.text)

                waf = detect_waf(self)
                self.detected_waf_name = waf.get('name')
                self.waf_is_blocking = 'Bloquant' in waf.get('behavior', {}).get('status', '')
                console.print(f"[bold yellow][*] WAF Détecté :[/bold yellow] [green]{self.detected_waf_name}[/green] "
                               f"| Statut : [bold]{waf.get('behavior', {}).get('status')}[/bold]")

                if self.config['cve']:
                    cves = search_cve(waf.get('name'))
                    print_cve_results(cves)
                    for cve in cves:
                        self.add_recon_finding(
                            "CVE publique (WAF)", current_target,
                            f"{cve['id']} [{cve['severity']}] (score {cve['score']}) — "
                            f"association par nom uniquement, à confirmer sur la version exacte."
                        )

            except Exception as e:
                if self.config['verbose']:
                    console.print(f"[bold red][ERR] Phase de détection WAF échouée sur {current_target}: {e}[/bold red]")
                self.config['target'] = original_target_conf
                continue

            if self.config['waf_only']:
                self.config['target'] = original_target_conf
                continue

            api_endpoints = []
            if self.config['api_scan']:
                api_endpoints = detect_api(self, current_target)

            points = []
            if self.config['crawl']:
                points = crawl_target(self)

            if api_endpoints and self.config['category']:
                params_fuzz = ['id', 'q', 'search', 'user', 'file', 'name', 'password', 'token']
                print(f"[*] Intégration de {len(api_endpoints)} APIs découvertes pour le fuzzing...")
                for api_url in api_endpoints:
                    if not any(p['url'] == api_url for p in points):
                        points.append({'url': api_url, 'method': 'GET', 'parameters': params_fuzz})

            if not points:
                parsed = urlparse(current_target)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                if self.config['data']:
                    post_qs = parse_qs(self.config['data'])
                    defaults = {k: v[0] for k, v in post_qs.items()}
                    params_list = list(defaults.keys())
                    print(f"[*] Paramètres POST détectés (avec valeurs) : {defaults}")
                    points.append({'url': clean_url, 'method': 'POST', 'parameters': params_list, 'defaults': defaults})
                elif parsed.query:
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    get_params = list(qs.keys())
                    if not get_params:
                        get_params = [p.split('=')[0] for p in parsed.query.split('&') if p]
                    if get_params:
                        print(f"[*] Paramètres GET détectés : {get_params}")
                        points.append({'url': clean_url, 'method': 'GET', 'parameters': get_params})

            if not points and self.config['category'] and clean_url:
                params_fuzz = ['id', 'q', 'search', 'view', 'page', 'file', 'cat', 'name', 'user']
                print(f"[*] Aucun paramètre détecté. Activation du Fuzzing sur : {params_fuzz}")
                points.append({'url': clean_url, 'method': 'GET', 'parameters': params_fuzz})

            if self.config['category']:
                print(f"[*] Lancement des tests sur {len(points)} points d'entrée...")
                if self.config['threads'] == 1:
                    print("[INFO] Mode Mono-thread (séquentiel pour débogage).")
                    for pt in points:
                        self._test_endpoint(pt)
                else:
                    print(f"[INFO] Mode Multi-thread ({self.config['threads']} workers).")
                    with ThreadPoolExecutor(max_workers=self.config['threads']) as ex:
                        futures = [ex.submit(self._test_endpoint, pt) for pt in points]
                        for f in as_completed(futures):
                            try:
                                f.result()
                            except Exception as e:
                                if self.config['verbose']:
                                    console.print(f"[bold red][ERR] Worker de test a levé une exception: {e}[/bold red]")
            else:
                print("[*] Pas de catégorie d'attaque spécifiée.")

            self.config['target'] = original_target_conf

    def _test_endpoint(self, point):
        cat = self.config['category']
        lvl = self.config['level']
        bypass = self.config['waf_bypass']
        waf_name = self.detected_waf_name

        for param in point['parameters']:
            if cat in ['all', 'sqli']: run_sqli_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'xss']: run_xss_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'ssti']: run_ssti_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'lfi']: run_lfi_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'ssrf']: run_ssrf_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'cmdi']: run_cmdi_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'nosqli']: run_nosqli_test(self, point, param, lvl, bypass, waf_name)
            if cat in ['all', 'csrf']: run_csrf_test(self, point, param, lvl, bypass)
            if cat in ['all', 'idor']: run_idor_test(self, point, param, lvl, bypass)
            if cat in ['all', 'smuggling']:
                run_smuggling_test(self, point, "Headers", lvl, bypass, waf_name)
