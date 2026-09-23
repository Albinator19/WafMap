from .tampering import apply_tampering
from . import bypass_oracle

CALC_A = 1337
CALC_B = 1337
TARGET_RESULT = str(CALC_A * CALC_B)


def load_payloads_from_file(filename="payloads/ssti.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception:
        return [f"{{{{{CALC_A}*{CALC_B}}}}}"]


def run_ssti_test(engine, point, param_name, level, bypass, waf_name=None):
    url = point['url']
    method = point['method']

    base_resp = engine._send_request(url, method=method)
    if base_resp is not None and TARGET_RESULT in base_resp.text:
        return

    data = {p: 'x' for p in point['parameters']} if method == 'POST' else None
    params = {p: 'x' for p in point['parameters']} if method == 'GET' else None
    oracle_base = data if method == 'POST' else params

    forced_technique = None
    if bypass:
        forced_technique = bypass_oracle.probe_and_get_technique(engine, url, method, oracle_base, param_name, 'ssti', waf_name)

    payloads = load_payloads_from_file()

    for payload in payloads:
        final_payload = apply_tampering(payload, 'ssti', bypass, waf_name, technique=forced_technique)

        if "1337" not in final_payload and "7*7" in final_payload:
            final_payload = final_payload.replace("7*7", f"{CALC_A}*{CALC_B}")

        if bypass:
            base = data if method == 'POST' else params
            resp = engine._send_request_raw(url, method, base, param_name, final_payload)
        else:
            if method == 'POST':
                data[param_name] = final_payload
            else:
                params[param_name] = final_payload
            resp = engine._send_request(url, method=method, data=data, params=params)

        if resp is not None and TARGET_RESULT in resp.text:
            details = f"Calcul exécuté ({TARGET_RESULT})"
            if bypass and forced_technique:
                details += f" - Technique de bypass utilisée : {forced_technique}"
            engine.add_vulnerability("SSTI", url, final_payload, details, parameter=param_name)
            return
