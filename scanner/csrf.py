from bs4 import BeautifulSoup

SESSION_COOKIE_HINTS = ['sess', 'sid', 'auth', 'token', 'phpsessid', 'jsessionid', 'connect.sid']


def _get_set_cookie_lines(resp):
    try:
        return resp.raw.headers.getlist('Set-Cookie')
    except Exception:
        raw = resp.headers.get('Set-Cookie')
        return [raw] if raw else []


def _session_cookie_has_samesite_protection(resp):
    for line in _get_set_cookie_lines(resp):
        if not line:
            continue
        low = line.lower()
        cookie_name = low.split('=')[0].strip()
        looks_like_session = any(hint in cookie_name for hint in SESSION_COOKIE_HINTS)
        if looks_like_session and ('samesite=strict' in low or 'samesite=lax' in low):
            return True
    return False


def run_csrf_test(engine, point, param_name, level, bypass):
    url = point['url']

    if not hasattr(engine, '_scanned_csrf_urls'):
        engine._scanned_csrf_urls = set()
    if url in engine._scanned_csrf_urls:
        return
    engine._scanned_csrf_urls.add(url)

    resp = engine._send_request(url, method="GET")
    if resp is None:
        return

    samesite_protected = _session_cookie_has_samesite_protection(resp)

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

            if has_token:
                continue

            action = form.get('action', '')

            if samesite_protected:
                engine.add_recon_finding(
                    "CSRF (protection SameSite détectée)", url,
                    f"Formulaire POST vers '{action}' sans token visible, mais un cookie de session porte "
                    "l'attribut SameSite=Strict/Lax : le risque CSRF classique est fortement réduit. "
                    "Vérifier manuellement l'absence de vérification Origin/Referer côté serveur si besoin."
                )
                continue

            engine.add_vulnerability(
                "CSRF (Absence de token)",
                url,
                "Formulaire HTML",
                f"Formulaire POST vers '{action}' sans token anti-CSRF visible dans le HTML et sans cookie de "
                "session en SameSite=Strict/Lax détecté. Vérifier aussi une éventuelle validation Origin/Referer "
                "côté serveur avant de considérer la faille comme exploitable.",
                parameter="Body",
                confidence="A vérifier"
            )
            return

    except Exception as e:
        if engine.config['verbose']:
            print(f"[ERR] Analyse CSRF échouée sur {url}: {e}")
