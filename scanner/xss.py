import re
from .tampering import apply_tampering
from . import bypass_oracle

XSS_MARKER = "WAFMAP_XSS"


def load_payloads_from_file(filename="payloads/xss.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return [f"<script>alert('{XSS_MARKER}')</script>"]


def _reflected_inside_html_comment(response_text, payload):
    for match in re.finditer(re.escape(payload), response_text):
        window_start = max(0, match.start() - 200)
        before = response_text[window_start:match.start()]
        last_open = before.rfind("<!--")
        last_close = before.rfind("-->")
        if last_open != -1 and last_open > last_close:
            continue
        return False
    return True


def validate_poc(response, payload, original_text):
    if XSS_MARKER not in response.text:
        return False

    if XSS_MARKER in original_text:
        return False

    content_type = response.headers.get('Content-Type', '').lower()
    if 'application/json' in content_type or 'text/plain' in content_type:
        return False

    response_lower = response.text.lower()
    payload_lower = payload.lower()

    if "<" in payload:
        if "&lt;" in response.text or "&#60;" in response.text or "%3c" in response_lower:
            encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if encoded_payload.lower() in response_lower:
                return False

    if "<" in payload and ">" in payload:
        if payload_lower not in response_lower:
            return False
        if _reflected_inside_html_comment(response.text, payload):
            return False

    return True


def run_xss_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']

    dummy = "WAFMAP_BASELINE"
    base_params = {p: dummy for p in injection_point['parameters']}

    base_resp = engine._send_request(url, method=method,
                                      data=base_params if method == 'POST' else None,
                                      params=base_params if method == 'GET' else None)
    original_text = base_resp.text if base_resp is not None else ""

    forced_technique = None
    if waf_bypass_enabled:
        forced_technique = bypass_oracle.probe_and_get_technique(
            engine, url, method, base_params, param_name, 'xss', waf_name
        )

    payloads = load_payloads_from_file()

    for payload in payloads:
        if engine.is_vector_confirmed('XSS', url, param_name):
            return

        curr_payload = payload.replace("WAFMAP_XSS_TEST_MARKER", XSS_MARKER)
        final_payload = apply_tampering(curr_payload, 'xss', waf_bypass_enabled, waf_name, technique=forced_technique)

        if waf_bypass_enabled:
            response = engine._send_request_raw(url, method, base_params, param_name, final_payload)
        else:
            data = dict(base_params)
            data[param_name] = final_payload
            response = engine._send_request(url, method=method,
                                              data=data if method == 'POST' else None,
                                              params=data if method == 'GET' else None)

        if response is not None and validate_poc(response, final_payload, original_text):
            details = ("Payload reflété sans encodage HTML hors contexte de commentaire (probable exécution). "
                        "Confirmation dans un navigateur recommandée pour un rapport final.")
            if waf_bypass_enabled and forced_technique:
                details += f" Technique de bypass utilisée : {forced_technique}."

            engine.add_vulnerability("XSS (Reflected)", url, final_payload, details, parameter=param_name)
            return
