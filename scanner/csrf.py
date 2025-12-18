from bs4 import BeautifulSoup

SCANNED_CSRF_URLS = set()

def run_csrf_test(engine, point, param_name, level, bypass):
    url = point['url']
    
    if url in SCANNED_CSRF_URLS:
        return
    SCANNED_CSRF_URLS.add(url)

    resp = engine._send_request(url, method="GET") 
    if not resp: return

    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            method = form.get('method', 'GET').upper()
            if method != 'POST':
                continue

            inputs = form.find_all('input', {'type': 'hidden'})
            has_token = False
            for i in inputs:
                name = i.get('name', '').lower()
                if any(x in name for x in ['csrf', 'token', 'nonce', 'xsrf', 'anti-forgery']):
                    has_token = True
                    break
            
            if not has_token:
                action = form.get('action', '')
                details = f"Formulaire POST vers '{action}' sans token anti-CSRF visible."
                
                engine.add_vulnerability(
                    "CSRF (Manque de Token)", 
                    url, 
                    "Formulaire HTML", 
                    details, 
                    parameter="Body"
                )
                return 
                
    except Exception as e:
        if engine.config['verbose']:
            print(f"[ERR] Analyse CSRF échouée sur {url}: {e}")
