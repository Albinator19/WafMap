import requests
import socket
import os 
from urllib.parse import urlparse

def get_ctl_subdomains(domain):
    print("[*] Recherche CTL (crt.sh)...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry['name_value']
                if "\n" in name:
                    name = name.split("\n")[0]
                if name.endswith(domain) and "*" not in name:
                    if " " not in name and "@" not in name:
                        subdomains.add(name)
    except Exception as e:
        print(f"[!] Erreur lors de la requête CTL : {e}")
    return list(subdomains)

def load_subdomains_from_file(filename="payloads/subdomains.txt"):
    default_list = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'm', 'shop', 'api', 'dev', 'test', 'admin']
    
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                subs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"    [*] Wordlist chargée : {len(subs)} sous-domaines.")
            return subs
        else:
            print(f"    [!] Fichier {filename} introuvable. Bascule sur la liste par défaut.")
            return default_list
    except Exception as e:
        print(f"    [!] Erreur de lecture de la wordlist : {e}")
        return default_list

def scan_subdomains(target_url, wordlist_path="payloads/subdomains.txt"):
    parsed = urlparse(target_url)
    domain = parsed.netloc.split(':')[0]
    
    print(f"[*] Scan de sous-domaines pour : {domain}")
    
    found_subdomains = set()

    ctl_subs = get_ctl_subdomains(domain)
    for sub in ctl_subs:
        found_subdomains.add(sub)
        print(f"    [+] CTL Trouvé : {sub}")

    prefixes = load_subdomains_from_file(wordlist_path)
    
    print(f"    [*] Lancement du Brute-force DNS ({len(prefixes)} tentatives)...")
    
    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"
        
        if subdomain in found_subdomains:
            continue
            
        try:
            socket.gethostbyname(subdomain)
            found_subdomains.add(subdomain)
            print(f"    [+] DNS Trouvé : {subdomain}")
        except socket.error:
            pass

    return list(found_subdomains)
