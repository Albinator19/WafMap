from bs4 import BeautifulSoup

# Cache global pour éviter de re-parser 10 fois la même page si elle a 10 paramètres différents
SCANNED_CSRF_URLS = set()

def run_csrf_test(engine, point, param_name, level, bypass):
    """
    Analyse les formulaires HTML pour détecter l'absence de tokens anti-CSRF.
    C'est une vérification passive (analyse du code source), pas d'attaque active.
    """
    url = point['url']
    
    # Optimisation : On ne scanne l'URL qu'une seule fois
    if url in SCANNED_CSRF_URLS:
        return
    SCANNED_CSRF_URLS.add(url)

    # Récupération du HTML. On utilise GET car on veut juste lire le DOM.
    resp = engine._send_request(url, method="GET") 
    if not resp: return

    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            # Le risque CSRF critique concerne principalement les modifications d'état (POST)
            method = form.get('method', 'GET').upper()
            if method != 'POST':
                continue

            # Recherche heuristique d'un token de sécurité
            inputs = form.find_all('input', {'type': 'hidden'})
            has_token = False
            for i in inputs:
                name = i.get('name', '').lower()
                # On cherche des patterns communs pour les tokens 
                if any(x in name for x in ['csrf', 'token', 'nonce', 'xsrf', 'anti-forgery']):
                    has_token = True
                    break
            
            # Si aucun champ caché ne ressemble à un token -> Vulnérabilité potentielle
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
                return # Pour éviter le spam, on signale une seule faille par page
                
    except Exception as e:
        if engine.config['verbose']:
            print(f"[ERR] Analyse CSRF échouée sur {url}: {e}")
