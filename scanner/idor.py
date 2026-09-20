import random
import difflib
from .tampering import apply_tampering

IDOR_PARAM_NAMES = ['id', 'uid', 'user_id', 'account', 'account_id', 'order_id',
                     'profile', 'invoice_id', 'doc_id', 'file_id', 'ref']

ERROR_MARKERS = ['not found', 'introuvable', 'unauthorized', 'forbidden', 'access denied',
                 'erreur', 'invalid', 'does not exist']


def _build_request_kwargs(point, param_name, value):
    method = point['method']
    data = {p: 'x' for p in point['parameters']} if method == 'POST' else None
    params = {p: 'x' for p in point['parameters']} if method == 'GET' else None
    if method == 'POST':
        data[param_name] = value
    else:
        params[param_name] = value
    return method, data, params


def _looks_like_error_page(text):
    low = text.lower()
    return any(m in low for m in ERROR_MARKERS)


def _similar(a, b):
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def run_idor_test(engine, point, param_name, level, bypass):
    if param_name.lower() not in IDOR_PARAM_NAMES:
        return

    url = point['url']
    method = point['method']

    invalid_id = str(random.randint(9_000_000, 9_999_999))
    m, data, params = _build_request_kwargs(point, param_name, invalid_id)
    baseline_invalid = engine._send_request(url, method=m, data=data, params=params)
    if baseline_invalid is None:
        return
    baseline_text = baseline_invalid.text
    baseline_is_error = _looks_like_error_page(baseline_text) or baseline_invalid.status_code != 200

    test_ids = ['1', '2', '3', '10']

    for tid in test_ids:
        if engine.is_vector_confirmed('IDOR', url, param_name):
            return

        m, data, params = _build_request_kwargs(point, param_name, tid)
        resp_owner = engine._send_request(url, method=m, data=data, params=params)
        if resp_owner is None or resp_owner.status_code != 200:
            continue
        if _looks_like_error_page(resp_owner.text):
            continue
        if _similar(resp_owner.text, baseline_text) > 0.95 and not baseline_is_error:
            continue

        if engine.second_session is not None:
            resp_second = engine._send_request(url, method=m, data=data, params=params, session=engine.second_session)
            if resp_second is None or resp_second.status_code != 200:
                continue
            if _looks_like_error_page(resp_second.text):
                continue
            if _similar(resp_second.text, baseline_text) > 0.95 and not baseline_is_error:
                continue
            if _similar(resp_owner.text, resp_second.text) > 0.85:
                engine.add_vulnerability(
                    "IDOR", url, tid,
                    "Le second compte (session distincte) accède au même objet que le compte de référence, "
                    "avec un contenu quasi identique et distinct de la réponse pour un identifiant inexistant.",
                    parameter=param_name,
                    confidence="Confirmée"
                )
                return
        else:
            engine.add_vulnerability(
                "IDOR (Potentiel)", url, tid,
                f"L'objet {tid} renvoie un contenu distinct de celui d'un identifiant clairement invalide "
                f"({invalid_id}), sans marqueur d'erreur. Aucune seconde session fournie (--second-session-cookie) : "
                "impossible de confirmer une violation d'autorisation entre comptes sans reproduire ce test manuellement "
                "avec deux comptes distincts.",
                parameter=param_name,
                confidence="A vérifier"
            )
            return
