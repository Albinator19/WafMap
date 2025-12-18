import socket
import requests
import urllib3
from urllib.parse import urlparse

# Suppression des warnings de vérification SSL, car on scanne souvent
# des environnements de dev ou des IPs directes avec certificats invalides
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_ports(target, ports_str):
    """
    Effectue un scan TCP Connect sur les ports cibles.
    Si un port est ouvert, tente d'identifier un service HTTP(S).
    """
    # Extraction propre du hostname pour le socket
    if "://" in target:
        hostname = urlparse(target).netloc.split(':')[0]
    else:
        hostname = target.split("/")[0].split(":")[0]

    # Parsing de la chaîne de ports CLI
    try:
        if not ports_str:
            return []
        ports = [int(p.strip()) for p in ports_str.split(',')]
    except ValueError:
        print(f"    [!] Erreur de format de ports. Utilisez --ports 80,443,8080")
        return []

    print(f"    [*] Scan des ports {ports} sur {hostname}...")
    
    web_services = []

    for port in ports:
        # 1. Test TCP Rapide (Socket)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Timeout très court (1s) pour éviter de bloquer le scan sur les ports filtrés
            sock.settimeout(1) 
            result = sock.connect_ex((hostname, port))
            sock.close()

            if result == 0:
                # Port ouvert au niveau TCP ! On vérifie la couche applicative (L7)
                service_url = identify_web_service(hostname, port)
                
                if service_url:
                    print(f"    [+] Port {port} \033[92mOUVERT\033[0m -> Service Web : {service_url}")
                    web_services.append(service_url)
                else:
                    print(f"    [+] Port {port} \033[92mOUVERT\033[0m (Service non-web ou inconnu)")

        except Exception as e:
            pass
            
    return web_services

def identify_web_service(hostname, port):
    """
    Heuristique simple pour déterminer le protocole (HTTP vs HTTPS).
    Essentiel pour scanner les panels d'admin sur ports exotiques (8443, 8080...).
    """
    # Ordre de préférence des protocoles
    protocols = ['http', 'https']
    
    # Optimisation : si port standard SSL, on teste HTTPS en premier
    if port in [443, 8443]:
        protocols = ['https', 'http']

    for proto in protocols:
        url = f"{proto}://{hostname}:{port}"
        try:
            # Requête HEAD : plus rapide et moins bruyante qu'un GET complet
            requests.head(url, timeout=2, verify=False, allow_redirects=True)
            return url
        except:
            continue
    
    return None
