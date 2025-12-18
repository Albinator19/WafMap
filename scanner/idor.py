def run_idor_test(engine, point, param_name, level, bypass):
    """
    Test de vulnérabilité IDOR (Insecure Direct Object Reference).
    Ici, on ne cherche pas à contourner le WAF, mais à exploiter une faille logique
    dans le contrôle d'accès de l'application.
    """
    
    # Filtrage : On ne teste que les paramètres qui ressemblent à des identifiants
    if param_name.lower() not in ['id', 'uid', 'user_id', 'account', 'order_id', 'profile']:
        return

    url = point['url']
    method = point['method']
    # Liste d'ID 
    test_ids = ['1', '0', '1000', 'admin', '10']
    
    for tid in test_ids:
        data = {p: 'x' for p in point['parameters']} if method=='POST' else None
        params = {p: 'x' for p in point['parameters']} if method=='GET' else None
        
        # On remplace l'ID légitime par notre ID cible
        if method=='POST': data[param_name] = tid
        else: params[param_name] = tid

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        # Analyse heuristique de la réussite
        if resp and resp.status_code == 200:
            # Si on accède à l'ID 0, 1, admin ... et qu'il y a du contenu (>20 chars)
            if tid in test_ids and len(resp.text) > 20:
                 # Vérification des faux positifs (pages d'erreur génériques soft-404)
                 if "not found" not in resp.text.lower() and "error" not in resp.text.lower():
                     engine.add_vulnerability(
                        "IDOR (Potentiel)", url, tid, 
                        f"Accès réussi à l'objet {tid} (Code 200).", parameter=param_name
                    )
