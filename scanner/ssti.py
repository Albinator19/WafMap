from .tampering import apply_tampering

CALC_A = 1337
CALC_B = 1337
TARGET_RESULT = str(CALC_A * CALC_B)

def load_payloads_from_file(filename="payloads/ssti.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except: 
        return [f"{{{{{CALC_A}*{CALC_B}}}}}"] 

def run_ssti_test(engine, point, param_name, level, bypass, waf_name=None):
    url = point['url']
    method = point['method']
    
    base_resp = engine._send_request(url, method=method)
    if base_resp and TARGET_RESULT in base_resp.text: return

    payloads = load_payloads_from_file()

    for payload in payloads:
        final_payload = apply_tampering(payload, 'ssti', bypass, waf_name)
        
        if "1337" not in final_payload and "7*7" in final_payload:
             final_payload = final_payload.replace("7*7", f"{CALC_A}*{CALC_B}")

        data = {p: 'x' for p in point['parameters']} if method == 'POST' else None
        params = {p: 'x' for p in point['parameters']} if method == 'GET' else None
        
        if method == 'POST': data[param_name] = final_payload
        else: params[param_name] = final_payload

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        if resp and TARGET_RESULT in resp.text:
            engine.add_vulnerability("SSTI", url, final_payload, f"Calcul exécuté ({TARGET_RESULT})", parameter=param_name)
