from .tampering import apply_tampering

XSS_MARKER = "WAFMAP_XSS"

def load_payloads_from_file(filename="payloads/xss.txt"):
    """Charge les payloads XSS depuis le fichier."""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        # Payload de secours minimaliste mais efficace
        return [f"<script>alert('{XSS_MARKER}')</script>"]

def validate_poc(response, payload, original_text):
    """
    Validation stricte de la vulnérabilité XSS.
    Objectif : Éliminer 100% des Faux Positifs (Encodage, Nettoyage, JSON).
    """
    # 1. Recherche du Marqueur unique
    if XSS_MARKER not in response.text:
        return False

    # 2. Diffing avec la baseline 
    # Si le marqueur était déjà sur la page avant l'injection, c'est un faux positif.
    if XSS_MARKER in original_text:
        return False

    # 3. Vérification du Contexte (Content-Type)
    # Si le payload est réfléchi dans du JSON ou du Texte brut, ce n'est pas une XSS exécutable.
    content_type = response.headers.get('Content-Type', '').lower()
    if 'application/json' in content_type or 'text/plain' in content_type:
        return False

    # 4. Vérification de l'Intégrité 
    response_lower = response.text.lower()
    payload_lower = payload.lower()

    # A. Détection d'Encodage HTML 
    # Si on injecte "<" et qu'on reçoit "&lt;" ou "&#60;", c'est sécurisé.
    if "<" in payload:
        if "&lt;" in response.text or "&#60;" in response.text or "%3c" in response_lower:
            encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if encoded_payload.lower() in response_lower:
                return False

    # B. Détection de Suppression
    # Si on injecte "<script>" et qu'on reçoit "script" (sans les chevrons), c'est sécurisé.
    if "<" in payload and ">" in payload:
        # On vérifie si la structure balisée est conservée
        if payload_lower not in response_lower:
            return False
    return True

def run_xss_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']
    
    # 1. Baseline pour le Diffing
    dummy = "WAFMAP_BASELINE"
    b_data = {p: dummy for p in injection_point['parameters']} if method == 'POST' else None
    b_params = {p: dummy for p in injection_point['parameters']} if method == 'GET' else None

    base_resp = engine._send_request(url, method=method, data=b_data, params=b_params)
    original_text = base_resp.text if base_resp else ""

    payloads = load_payloads_from_file()

    for payload in payloads:
        # Préparation du payload avec le marqueur unique
        curr_payload = payload.replace("WAFMAP_XSS_TEST_MARKER", XSS_MARKER)
        
        # Application du Bypass 
        final_payload = apply_tampering(curr_payload, 'xss', waf_bypass_enabled, waf_name)
        
        # Configuration des données
        data = b_data.copy() if b_data else None
        params = b_params.copy() if b_params else None
        
        if method == 'POST': data[param_name] = final_payload
        else: params[param_name] = final_payload

        # Envoi de l'attaque
        response = engine._send_request(url, method=method, data=data, params=params)
        
        # Analyse stricte
        if response and validate_poc(response, final_payload, original_text):
            engine.add_vulnerability(
                "XSS (Reflected)", 
                url, 
                final_payload, 
                "Payload reflété sans encodage HTML (Executable)", 
                parameter=param_name
            )
