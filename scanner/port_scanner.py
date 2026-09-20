import socket
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_ports(target, ports_str):
    if "://" in target:
        hostname = urlparse(target).netloc.split(':')[0]
    else:
        hostname = target.split("/")[0].split(":")[0]

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
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1) 
            result = sock.connect_ex((hostname, port))
            sock.close()

            if result == 0:
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
    protocols = ['http', 'https']
    
    if port in [443, 8443]:
        protocols = ['https', 'http']

    for proto in protocols:
        url = f"{proto}://{hostname}:{port}"
        try:
            requests.head(url, timeout=2, verify=False, allow_redirects=True)
            return url
        except Exception:
            continue
    
    return None
