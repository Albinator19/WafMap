import requests
import time
import urllib3
import sys
import os
from urllib.parse import urlparse, parse_qs
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

# On désactive la vérification SSL fréquente en pentest interne/dev
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import des modules de sécurité développés dans le projet
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

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

class Engine:
    def __init__(self, args):
        """
        Initialisation du moteur de scan.
        Configure la session HTTP globale pour optimiser les performances (Keep-Alive).
        """
        self.config = self._load_config(args)
        
        # Utilisation d'une session persistante pour réutiliser les connexions TCP
        self.session = requests.Session()
        
        # CRUCIAL : trust_env=False empêche requests d'utiliser les proxies système
        # (évite les conflits si on scanne localhost ou si on est derrière un VPN d'entreprise)
        self.session.trust_env = False 
        
        # Configuration des headers par défaut pour imiter un navigateur ou s'identifier
        ua = self.config['user_agent'] if self.config['user_agent'] else 'WAFMap/1.0'
        self.session.headers.update({
            'User-Agent': ua,
            'Connection': 'close',
            'Accept': '*/*'
        })

        # Configuration du proxy
        if self.config['proxy']:
            self.session.proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }
            if self.config['verbose']: print(f"[CONF] Proxy configuré : {self.config['proxy']}")

        # Injection de headers personnalisés
        if self.config['headers_file']:
            self._load_custom_headers(self.config['headers_file'])

        # Stratégie de résilience : Retry automatique sur les erreurs de connexion (3 tentatives)
        adapter = HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.verify_ssl = False
        self.vulnerabilities = []
        self.detected_waf_name = None 
        self.csrf_token = None

    def _load_config(self, args):
        # Centralisation des arguments CLI dans un dictionnaire de configuration
        return {
            'target': args.target.rstrip('/'),
            'threads': min(args.threads, 50), # Eviter le DoS involontaire
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
            'match_text': args.match_text
        }
    
    def _fetch_csrf_token(self, html_text):
        """Recherche et stocke un jeton de sécurité caché dans la réponse HTML."""
        if not html_text: return
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            
            # Recherche des champs cachés classiques
            for input_tag in soup.find_all('input', {'type': 'hidden'}):
                name = input_tag.get('name', '').lower()
                value = input_tag.get('value', '')
                
                # Patterns typiques pour les tokens
                if any(x in name for x in ['csrf', 'token', 'nonce', 'user_token']) and value:
                    self.csrf_token = {name: value}
                    if self.config['verbose']:
                        print(f"[CONF] Jeton CSRF trouvé: {name}")
                    return
        except Exception as e:
            if self.config['verbose']: print(f"[ERR] Échec du parsing CSRF: {e}")

    def _load_custom_headers(self, filepath):
        """Parse un fichier texte pour charger des entêtes HTTP additionnels."""
        if not os.path.exists(filepath):
            print(f"[!] Fichier headers introuvable : {filepath}")
            return
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        self.session.headers.update({k.strip(): v.strip()})
            if self.config['verbose']: print(f"[CONF] Headers chargés depuis {filepath}")
        except Exception as e:
            print(f"[!] Erreur lecture headers : {e}")

    def _send_request(self, url, method="GET", data=None, params=None, attempt=1):
        """
        Wrapper central pour l'envoi de requêtes.
        Gère les Timeouts, les erreurs réseaux et les mécanismes de back-off (attente) en cas de 429.
        """
        try:
            # Si des data sont fournies globalement, on force la méthode POST
            if method == "GET" and self.config['data'] and data is None:
                 method = "POST"
                 data = self.config['data']

            if self.config['verbose']:
                print(f"[REQ] {method} {url} | P:{params} D:{data}")

            # Temporisation artificielle en mono-thread pour la discrétion
            if self.config['threads'] == 1: time.sleep(0.05)

            response = self.session.request(
                method, url, data=data, params=params, 
                timeout=self.config['timeout'], verify=self.verify_ssl, allow_redirects=True
            )
            
            # Gestion basique du Rate-Limiting (Too Many Requests / Service Unavailable)
            # On attend exponentiellement avant de réessayer
            if response.status_code in [429, 503] and attempt <= 3:
                time.sleep(2 * attempt)
                return self._send_request(url, method, data, params, attempt + 1)
            
            return response
            
        except requests.exceptions.Timeout:
            if self.config['verbose']: console.print(f"[bold red][TIMEOUT] {url}[/bold red]")
            return None
        except Exception as e:
            if self.config['verbose']: console.print(f"[bold red][ERR] {url}: {e}[/bold red]")
            return None

    def check_custom_validation(self, response):
        """Vérification des critères de succès personnalisés (--match-code / --match-text)."""
        if not response: return
        matched = False
        reasons = []
        
        if self.config['match_code'] and response.status_code == self.config['match_code']:
            matched = True
            reasons.append(f"Code {response.status_code}")
        
        if self.config['match_text'] and self.config['match_text'] in response.text:
            matched = True
            reasons.append(f"Texte '{self.config['match_text']}' trouvé")

        if matched:
            self.add_vulnerability("CUSTOM CHECK", response.url, self.config['data'] or "GET", f"Validé: {', '.join(reasons)}", parameter="Manual")

    def add_vulnerability(self, type_, url, payload, details, parameter=None):
        """Enregistre une vulnérabilité détectée et l'affiche dans la console."""
        # Mécanisme de déduplication pour éviter de retrouver plusieurs fois la même vulnérabilité
        for v in self.vulnerabilities:
            if v['type'] == type_ and v['url'] == url and v.get('parameter') == parameter and v['payload'] == payload:
                return

        vuln = {
            "type": type_, "url": url, "parameter": parameter,
            "payload": payload, "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerabilities.append(vuln)
        
        # Feedback visuel immédiat pour l'utilisateur
        # Création d'un tableau interne pour les détails
        grid = Table.grid(padding=(0, 1))
        grid.add_column(style="cyan", justify="right")
        grid.add_column(style="white")

        grid.add_row("URL :", url)
        if parameter:
            grid.add_row("Paramètre :", parameter)
        grid.add_row("Payload :", payload)
        grid.add_row("Détails :", details)

        # Affichage dans un panneau vert (succès)
        console.print(Panel(
            grid,
            title=f"[bold red]VULNÉRABILITÉ CONFIRMÉE : {type_}",
            border_style="red",
            expand=False
        ))

    def start_scan(self):
        """
        Orchestration principale du scanner.
        Étapes : Découverte -> Détection WAF -> Crawl -> Fuzzing/Attaque -> Rapport.
        """
        console.print(f"[bold blue][*] Démarrage du scan sur [white]{self.config['target']}[/white][/bold blue]")
        
        # Phase : Découverte de surface d'attaque 
        target_urls = [self.config['target']]
        
        # Scan de ports pour trouver des services web cachés (ex: 8080, 8443)
        if self.config['ports']:
            print("\n=== PHASE: SCAN DE PORTS ===")
            target_urls.extend(scan_ports(self.config['target'], self.config['ports']))

        # Énumération des sous-domaines
        if self.config['subdomains']:
            print("\n=== PHASE: SOUS-DOMAINES ===")
            subs = scan_subdomains(self.config['target'])
            for sub in subs:
                target_urls.append(f"http://{sub}" if not sub.startswith("http") else sub)

        # Suppression des doublons
        target_urls = sorted(list(set(target_urls)))

        # Boucle principale sur chaque cible identifiée 
        for current_target in target_urls:
            print(f"\n>>> ANALYSE DE : {current_target}")
            
            try:
                parsed = urlparse(current_target)
                base = f"{parsed.scheme}://{parsed.netloc}"
                
                # Sauvegarde temporaire de la config cible pour ce cycle
                original_target_conf = self.config['target']
                self.config['target'] = current_target

                # Test de disponibilité 
                base_method = "POST" if self.config['data'] else "GET"
                resp = self._send_request(current_target, method=base_method, data=self.config['data'])
                
                if not resp:
                    print("[!] Cible inaccessible. On passe.")
                    self.config['target'] = original_target_conf
                    continue
                
                # Vérification custom
                if self.config['match_code'] or self.config['match_text']:
                    self.check_custom_validation(resp)
                
                self._fetch_csrf_token(resp.text)

                # 1. Détection WAF
                waf = detect_waf(self)
                self.detected_waf_name = waf.get('name')
                console.print(f"[bold yellow][*] WAF Détecté :[/bold yellow] [green]{self.detected_waf_name}[/green] | Statut : [bold]{waf.get('behavior', {}).get('status')}[/bold]")
                
                # 2. Recherche de CVE connues pour ce WAF
                if self.config['cve']:
                    cves = search_cve(waf.get('name'))
                    print_cve_results(cves)
                    for cve in cves:
                         self.add_vulnerability("CVE WAF", current_target, cve['id'], f"{cve['severity']}...", parameter="WAF")

            except: pass

            if self.config['waf_only']:
                self.config['target'] = original_target_conf
                continue

            # Détection d'endpoints API
            api_endpoints = []
            if self.config['api_scan']: 
                api_endpoints=detect_api(self, current_target)

            # Phase: Crawling & Extraction de paramètres 
            points = []
            if self.config['crawl']:
                orig = self.config['target']
                self.config['target'] = current_target 
                points = crawl_target(self)
                self.config['target'] = orig
            
            if api_endpoints and self.config['category']:
                params_fuzz = ['id', 'q', 'search', 'user', 'file', 'name', 'password', 'token'] 
                print(f"[*] Intégration de {len(api_endpoints)} APIs découvertes pour le fuzzing...")
                
                for api_url in api_endpoints:
                    # On évite les doublons si le crawler les a déjà pris
                    if not any(p['url'] == api_url for p in points):
                        points.append({
                            'url': api_url, 
                            'method': 'GET', 
                            'parameters': params_fuzz 
                        })
        
            # Fallback : Si le crawl ne trouve rien, on devine des paramètres communs 
            if not points:
                parsed = urlparse(current_target)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                if self.config['data']:
                    post_qs = parse_qs(self.config['data']) 
                    defaults = {k: v[0] for k, v in post_qs.items()}
                    params_list = list(defaults.keys())
                    
                    print(f"[*] Paramètres POST détectés (avec valeurs) : {defaults}")
                    
                    points.append({
                        'url': clean_url, 
                        'method': 'POST', 
                        'parameters': params_list,
                        'defaults': defaults # On stocke les valeurs originales
                    })
                elif parsed.query:
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    get_params = list(qs.keys())
                    
                    if not get_params:
                        get_params = [p.split('=')[0] for p in parsed.query.split('&') if p]
                    
                    if get_params:
                        print(f"[*] Paramètres GET détectés : {get_params}")
                        points.append({'url': clean_url, 'method': 'GET', 'parameters': get_params})

            if not points and self.config['category']:
                params_fuzz = ['id', 'q', 'search', 'view', 'page', 'file', 'cat', 'name', 'user']
                print(f"[*] Aucun paramètre détecté. Activation du Fuzzing sur : {params_fuzz}")
                points.append({
                    'url': clean_url, 
                    'method': 'GET', 
                    'parameters': params_fuzz
                })

            # Phase: Attaques Actives 
            if self.config['category']:
                print(f"[*] Lancement des tests sur {len(points)} points d'entrée...")
                
                if self.config['threads'] == 1:
                    print("[INFO] Mode Mono-thread (séquentiel pour débogage).")
                    for pt in points: self._test_endpoint(pt)
                else:
                    # Exécution parallèle via ThreadPoolExecutor pour accélérer le scan
                    print(f"[INFO] Mode Multi-thread ({self.config['threads']} workers).")
                    with ThreadPoolExecutor(max_workers=self.config['threads']) as ex:
                        futures = [ex.submit(self._test_endpoint, pt) for pt in points]
                        # On s'assure que les threads se terminent proprement
                        for f in as_completed(futures):
                            try: f.result()
                            except: pass
            else:
                print("[*] Pas de catégorie d'attaque spécifiée.")

            # Rétablissement de la cible d'origine pour le prochain tour de boucle
            self.config['target'] = original_target_conf

        print(f"\n[*] Scan terminé. {len(self.vulnerabilities)} vulnérabilités.")
        
        # Génération du rapport si demandé
        if self.config['output']: 
            generate_report(self)

    def _test_endpoint(self, point):
        """
        Fonction exécutée par chaque thread.
        Lance les modules d'attaque spécifiques selon la catégorie choisie.
        """
        cat = self.config['category']
        lvl = self.config['level']
        bypass = self.config['waf_bypass']
        
        # On passe le nom du WAF détecté pour activer le tampering 
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
