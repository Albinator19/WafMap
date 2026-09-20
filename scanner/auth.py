from urllib.parse import parse_qsl


def _parse_body(raw):
    if not raw:
        return {}
    return dict(parse_qsl(raw, keep_blank_values=True))


def perform_login(engine):
    cfg = engine.config
    login_url = cfg.get('login_url')
    if not login_url:
        return None

    login_data = _parse_body(cfg.get('login_data'))

    try:
        resp = engine._send_request(login_url, method="POST", data=login_data)
    except Exception as e:
        print(f"[AUTH] [!] Erreur réseau pendant le login : {e}")
        return False

    if resp is None:
        print("[AUTH] [!] Aucune réponse du serveur pendant le login.")
        return False

    success_text = cfg.get('login_success_text')
    if success_text:
        ok = success_text.lower() in resp.text.lower()
    else:
        fail_markers = ["invalid", "incorrect", "erreur", "échec", "failed"]
        has_fail_marker = any(m in resp.text.lower() for m in fail_markers)
        has_new_cookie = len(engine.session.cookies) > 0
        ok = has_new_cookie and not has_fail_marker

    if ok:
        print(f"[AUTH] [+] Login réussi sur {login_url} (session conservée pour le scan).")
    else:
        print(f"[AUTH] [!] Login probablement échoué sur {login_url} "
              f"(code {resp.status_code}). Le scan continue en mode non-authentifié. "
              f"Utilisez --login-success-text pour affiner la détection.")

    return ok
