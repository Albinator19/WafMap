import requests
import socket
import os 
from urllib.parse import urlparse

def get_ctl_subdomains(domain):
    """
    Récupération passive des sous-domaines via les logs de transparence de certificats (CT Logs).
    Source : crt.sh. Cette méthode est non-intrusive.
    """
    print("[*] Recherche CTL (crt.sh)...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry['name_value']
                # Nettoyage des entrées multilignes éventuelles
                if "\n" in name:
                    name = name.split("\n")[0]
                # Filtrage : on ne conserve que les sous-domaines valides (pas de wildcard)
                if name.endswith(domain) and "*" not in name:
                    if " " not in name and "@" not in name:
                        subdomains.add(name)
    except Exception as e:
        print(f"[!] Erreur lors de la requête CTL : {e}")
    return list(subdomains)

def load_subdomains_from_file(filename="payloads/subdomains.txt"):
    """
    Charge la wordlist de sous-domaines pour le brute-force. Si le fichier est absent, utilise une liste par défaut.
    """
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
    """
    Fonction principale d'énumération des sous-domaines.
    Combine l'approche passive (CTL) et active (DNS Brute-force).
    """
    parsed = urlparse(target_url)
    domain = parsed.netloc.split(':')[0] # Extraction du domaine sans le port
    
    print(f"[*] Scan de sous-domaines pour : {domain}")
    
    found_subdomains = set()

    # 1. Méthode CTL (Reconnaissance Passive)
    ctl_subs = get_ctl_subdomains(domain)
    for sub in ctl_subs:
        found_subdomains.add(sub)
        print(f"    [+] CTL Trouvé : {sub}")

    # 2. Méthode Brute-Force (Reconnaissance Active)
    prefixes = load_subdomains_from_file(wordlist_path)
    
    print(f"    [*] Lancement du Brute-force DNS ({len(prefixes)} tentatives)...")
    
    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"
        
        # Optimisation : éviter de tester un sous-domaine déjà découvert passivement
        if subdomain in found_subdomains:
            continue
            
        try:
            # Résolution DNS pour valider l'existence du sous-domaine
            socket.gethostbyname(subdomain)
            found_subdomains.add(subdomain)
            print(f"    [+] DNS Trouvé : {subdomain}")
        except socket.error:
            # Le sous-domaine ne résout pas, on passe au suivant
            pass

    return list(found_subdomains)
